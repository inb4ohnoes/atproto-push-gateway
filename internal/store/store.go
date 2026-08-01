package store

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type PushToken struct {
	ActorDID  string
	Platform  string
	PushToken string
	AppID     string
}

type Block struct {
	BlockerDID string
	BlockedDID string
	RKey       string
}

type DMEnrollment struct {
	ActorDID             string
	PDSHost              string
	EncryptedCredentials []byte
	State                string
}

type PendingChatMessage struct {
	RecipientDID     string
	ActorDID         string
	ConversationID   string
	MessageID        string
	ActorDisplayName string
	ActorHandle      string
	ActorAvatar      string
}

type Store struct {
	db                  *sql.DB
	mu                  sync.RWMutex
	registeredDIDs      map[string]bool
	blocks              map[string]map[string]bool   // blocker -> blocked -> true
	blocksByRKey        map[string]map[string]string // blocker -> rkey -> blocked
	verificationsByRKey map[string]map[string]string // verifier -> rkey -> subject
}

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS push_tokens (
			actor_did TEXT NOT NULL,
			platform TEXT NOT NULL CHECK (platform IN ('ios', 'android', 'web')),
			push_token TEXT NOT NULL,
			app_id TEXT NOT NULL,
			created_at TEXT DEFAULT (datetime('now')),
			updated_at TEXT DEFAULT (datetime('now')),
			PRIMARY KEY (actor_did, push_token)
		);
		CREATE TABLE IF NOT EXISTS blocks (
			blocker_did TEXT NOT NULL,
			blocked_did TEXT NOT NULL,
			rkey TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (blocker_did, blocked_did)
		);
		CREATE INDEX IF NOT EXISTS idx_blocks_rkey ON blocks (blocker_did, rkey);
		CREATE TABLE IF NOT EXISTS verifications (
			verifier_did TEXT NOT NULL,
			subject_did TEXT NOT NULL,
			rkey TEXT NOT NULL,
			PRIMARY KEY (verifier_did, rkey)
		);
		CREATE TABLE IF NOT EXISTS blocks_backfilled (
			actor_did TEXT PRIMARY KEY,
			backfilled_at TEXT DEFAULT (datetime('now'))
		);
		CREATE TABLE IF NOT EXISTS dm_enrollments (
			actor_did TEXT PRIMARY KEY,
			pds_host TEXT NOT NULL,
			encrypted_credentials BLOB,
			state TEXT NOT NULL CHECK (state IN ('active', 'needs_reauth')),
			created_at TEXT DEFAULT (datetime('now')),
			updated_at TEXT DEFAULT (datetime('now'))
		);
		CREATE TABLE IF NOT EXISTS chat_cursors (
			actor_did TEXT PRIMARY KEY,
			cursor TEXT NOT NULL DEFAULT '',
			updated_at TEXT DEFAULT (datetime('now')),
			FOREIGN KEY (actor_did) REFERENCES dm_enrollments(actor_did) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS chat_message_dedup (
			recipient_did TEXT NOT NULL,
			message_id TEXT NOT NULL,
			convo_id TEXT NOT NULL,
			actor_did TEXT NOT NULL,
			actor_display_name TEXT NOT NULL DEFAULT '',
			actor_handle TEXT NOT NULL DEFAULT '',
			actor_avatar TEXT NOT NULL DEFAULT '',
			delivered INTEGER NOT NULL DEFAULT 0,
			created_at TEXT DEFAULT (datetime('now')),
			PRIMARY KEY (recipient_did, message_id)
		);
		CREATE TABLE IF NOT EXISTS chat_message_deliveries (
			recipient_did TEXT NOT NULL,
			message_id TEXT NOT NULL,
			token_key TEXT NOT NULL,
			delivered_at TEXT DEFAULT (datetime('now')),
			PRIMARY KEY (recipient_did, message_id, token_key)
		);
	`); err != nil {
		return nil, err
	}

	s := &Store{
		db:                  db,
		registeredDIDs:      make(map[string]bool),
		blocks:              make(map[string]map[string]bool),
		blocksByRKey:        make(map[string]map[string]string),
		verificationsByRKey: make(map[string]map[string]string),
	}

	// loadIntoMemory is called without holding locks because the Store has not
	// been returned yet — no other goroutine can have a reference to it, so
	// there is no concurrent access at this point.
	if err := s.loadIntoMemory(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) UpsertDMEnrollment(enrollment DMEnrollment) error {
	_, err := s.db.Exec(`
		INSERT INTO dm_enrollments (actor_did, pds_host, encrypted_credentials, state, updated_at)
		VALUES (?, ?, ?, ?, datetime('now'))
		ON CONFLICT(actor_did) DO UPDATE SET
			pds_host = excluded.pds_host,
			encrypted_credentials = excluded.encrypted_credentials,
			state = excluded.state,
			updated_at = datetime('now')`,
		enrollment.ActorDID, enrollment.PDSHost, enrollment.EncryptedCredentials, enrollment.State,
	)
	return err
}

func (s *Store) GetDMEnrollment(actorDID string) (DMEnrollment, bool, error) {
	var enrollment DMEnrollment
	err := s.db.QueryRow(`
		SELECT actor_did, pds_host, encrypted_credentials, state
		FROM dm_enrollments WHERE actor_did = ?`, actorDID,
	).Scan(&enrollment.ActorDID, &enrollment.PDSHost, &enrollment.EncryptedCredentials, &enrollment.State)
	if err == sql.ErrNoRows {
		return DMEnrollment{}, false, nil
	}
	return enrollment, err == nil, err
}

func (s *Store) ListActiveDMEnrollments() ([]DMEnrollment, error) {
	rows, err := s.db.Query(`
		SELECT actor_did, pds_host, encrypted_credentials, state
		FROM dm_enrollments WHERE state = 'active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var enrollments []DMEnrollment
	for rows.Next() {
		var enrollment DMEnrollment
		if err := rows.Scan(&enrollment.ActorDID, &enrollment.PDSHost, &enrollment.EncryptedCredentials, &enrollment.State); err != nil {
			return nil, err
		}
		enrollments = append(enrollments, enrollment)
	}
	return enrollments, rows.Err()
}

func (s *Store) RevokeDMEnrollment(actorDID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM chat_cursors WHERE actor_did = ?", actorDID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM chat_message_dedup WHERE recipient_did = ?", actorDID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM chat_message_deliveries WHERE recipient_did = ?", actorDID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM dm_enrollments WHERE actor_did = ?", actorDID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SaveChatPage(actorDID, cursor string, messages []PendingChatMessage) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, message := range messages {
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO chat_message_dedup (
				recipient_did, message_id, convo_id, actor_did,
				actor_display_name, actor_handle, actor_avatar
			) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			message.RecipientDID, message.MessageID, message.ConversationID, message.ActorDID,
			message.ActorDisplayName, message.ActorHandle, message.ActorAvatar,
		); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`
		INSERT INTO chat_cursors (actor_did, cursor, updated_at) VALUES (?, ?, datetime('now'))
		ON CONFLICT(actor_did) DO UPDATE SET cursor = excluded.cursor, updated_at = datetime('now')`,
		actorDID, cursor,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetPendingChatMessages(actorDID string) ([]PendingChatMessage, error) {
	rows, err := s.db.Query(`
		SELECT recipient_did, actor_did, convo_id, message_id,
		       actor_display_name, actor_handle, actor_avatar
		FROM chat_message_dedup
		WHERE recipient_did = ? AND delivered = 0
		ORDER BY created_at, message_id`, actorDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var messages []PendingChatMessage
	for rows.Next() {
		var message PendingChatMessage
		if err := rows.Scan(
			&message.RecipientDID, &message.ActorDID, &message.ConversationID, &message.MessageID,
			&message.ActorDisplayName, &message.ActorHandle, &message.ActorAvatar,
		); err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

func (s *Store) MarkChatMessageDelivered(recipientDID, messageID string) error {
	_, err := s.db.Exec(`
		UPDATE chat_message_dedup SET delivered = 1
		WHERE recipient_did = ? AND message_id = ?`, recipientDID, messageID)
	return err
}

func (s *Store) HasChatMessageTokenDelivery(recipientDID, messageID, tokenKey string) (bool, error) {
	var exists int
	err := s.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM chat_message_deliveries
			WHERE recipient_did = ? AND message_id = ? AND token_key = ?
		)`, recipientDID, messageID, tokenKey).Scan(&exists)
	return exists == 1, err
}

func (s *Store) MarkChatMessageTokenDelivered(recipientDID, messageID, tokenKey string) error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO chat_message_deliveries (recipient_did, message_id, token_key)
		VALUES (?, ?, ?)`, recipientDID, messageID, tokenKey)
	return err
}

func (s *Store) MarkDMEnrollmentNeedsReauth(actorDID string) error {
	_, err := s.db.Exec(`
		UPDATE dm_enrollments
		SET encrypted_credentials = NULL, state = 'needs_reauth', updated_at = datetime('now')
		WHERE actor_did = ?`, actorDID)
	return err
}

func (s *Store) GetChatCursor(actorDID string) (string, error) {
	var cursor string
	err := s.db.QueryRow("SELECT cursor FROM chat_cursors WHERE actor_did = ?", actorDID).Scan(&cursor)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return cursor, err
}

func (s *Store) SetChatCursor(actorDID, cursor string) error {
	_, err := s.db.Exec(`
		INSERT INTO chat_cursors (actor_did, cursor, updated_at) VALUES (?, ?, datetime('now'))
		ON CONFLICT(actor_did) DO UPDATE SET cursor = excluded.cursor, updated_at = datetime('now')`,
		actorDID, cursor,
	)
	return err
}

func (s *Store) loadIntoMemory() error {
	// Load registered DIDs
	rows, err := s.db.Query("SELECT DISTINCT actor_did FROM push_tokens")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var did string
		if err := rows.Scan(&did); err != nil {
			return err
		}
		s.registeredDIDs[did] = true
	}

	// Load blocks
	blockRows, err := s.db.Query("SELECT blocker_did, blocked_did, rkey FROM blocks")
	if err != nil {
		return err
	}
	defer blockRows.Close()
	for blockRows.Next() {
		var blocker, blocked, rkey string
		if err := blockRows.Scan(&blocker, &blocked, &rkey); err != nil {
			return err
		}
		if s.blocks[blocker] == nil {
			s.blocks[blocker] = make(map[string]bool)
		}
		s.blocks[blocker][blocked] = true
		if rkey != "" {
			if s.blocksByRKey[blocker] == nil {
				s.blocksByRKey[blocker] = make(map[string]string)
			}
			s.blocksByRKey[blocker][rkey] = blocked
		}
	}

	// Load verifications
	verifRows, err := s.db.Query("SELECT verifier_did, rkey, subject_did FROM verifications")
	if err != nil {
		return err
	}
	defer verifRows.Close()
	for verifRows.Next() {
		var verifier, rkey, subject string
		if err := verifRows.Scan(&verifier, &rkey, &subject); err != nil {
			return err
		}
		if s.verificationsByRKey[verifier] == nil {
			s.verificationsByRKey[verifier] = make(map[string]string)
		}
		s.verificationsByRKey[verifier][rkey] = subject
	}

	return nil
}

const maxTokensPerDID = 20

func (s *Store) RegisterToken(actorDID, platform, pushToken, appID string) error {
	// Enforce per-DID cap. An upsert on the same (actor_did, push_token) does
	// not grow the count, so count excluding the same token before insert.
	// Wrap the count+insert pair in a transaction so concurrent registrations
	// for the same DID can't each see existing < cap and all insert, which
	// would overshoot the cap by up to N-1.
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existing int
	if err := tx.QueryRow(
		"SELECT COUNT(*) FROM push_tokens WHERE actor_did = ? AND push_token != ?",
		actorDID, pushToken,
	).Scan(&existing); err != nil {
		return err
	}
	if existing >= maxTokensPerDID {
		return fmt.Errorf("DID %s already has %d tokens (cap: %d)", actorDID, existing, maxTokensPerDID)
	}

	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO push_tokens (actor_did, platform, push_token, app_id, updated_at)
		 VALUES (?, ?, ?, ?, datetime('now'))`,
		actorDID, platform, pushToken, appID,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.mu.Lock()
	s.registeredDIDs[actorDID] = true
	s.mu.Unlock()

	return nil
}

func (s *Store) UnregisterToken(actorDID, platform, pushToken, appID string) error {
	_, err := s.db.Exec(
		`DELETE FROM push_tokens WHERE actor_did = ? AND platform = ? AND push_token = ? AND app_id = ?`,
		actorDID, platform, pushToken, appID,
	)
	if err != nil {
		return err
	}

	// Check if DID still has any tokens
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM push_tokens WHERE actor_did = ?", actorDID).Scan(&count)
	if count == 0 {
		s.mu.Lock()
		delete(s.registeredDIDs, actorDID)
		s.mu.Unlock()
	}

	return nil
}

func (s *Store) IsRegistered(did string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registeredDIDs[did]
}

func (s *Store) HasRegisteredDIDs() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.registeredDIDs) > 0
}

func (s *Store) GetTokensForDID(did string) ([]PushToken, error) {
	rows, err := s.db.Query(
		"SELECT actor_did, platform, push_token, app_id FROM push_tokens WHERE actor_did = ?",
		did,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []PushToken
	for rows.Next() {
		var t PushToken
		if err := rows.Scan(&t.ActorDID, &t.Platform, &t.PushToken, &t.AppID); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

func (s *Store) AddBlock(blockerDID, blockedDID, rkey string) error {
	_, err := s.db.Exec(
		"INSERT OR IGNORE INTO blocks (blocker_did, blocked_did, rkey) VALUES (?, ?, ?)",
		blockerDID, blockedDID, rkey,
	)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.blocks[blockerDID] == nil {
		s.blocks[blockerDID] = make(map[string]bool)
	}
	s.blocks[blockerDID][blockedDID] = true
	if rkey != "" {
		if s.blocksByRKey[blockerDID] == nil {
			s.blocksByRKey[blockerDID] = make(map[string]string)
		}
		s.blocksByRKey[blockerDID][rkey] = blockedDID
	}
	s.mu.Unlock()

	return nil
}

// MarkBlocksBackfilled records that this DID's historical blocks have been
// fetched. Returns true if the row was newly inserted (i.e. this caller
// should perform the backfill), false if already done.
func (s *Store) MarkBlocksBackfilled(actorDID string) (bool, error) {
	res, err := s.db.Exec(
		"INSERT OR IGNORE INTO blocks_backfilled (actor_did) VALUES (?)",
		actorDID,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RemoveBlockByRKey looks up a block by blocker DID and rkey, then removes it.
// Returns the blocked DID if found, or empty string if not found.
func (s *Store) RemoveBlockByRKey(blockerDID, rkey string) (string, error) {
	s.mu.RLock()
	blockedDID := ""
	if s.blocksByRKey[blockerDID] != nil {
		blockedDID = s.blocksByRKey[blockerDID][rkey]
	}
	s.mu.RUnlock()

	if blockedDID == "" {
		return "", nil
	}

	if err := s.RemoveBlock(blockerDID, blockedDID); err != nil {
		return "", err
	}

	s.mu.Lock()
	if s.blocksByRKey[blockerDID] != nil {
		delete(s.blocksByRKey[blockerDID], rkey)
	}
	s.mu.Unlock()

	return blockedDID, nil
}

func (s *Store) RemoveBlock(blockerDID, blockedDID string) error {
	_, err := s.db.Exec(
		"DELETE FROM blocks WHERE blocker_did = ? AND blocked_did = ?",
		blockerDID, blockedDID,
	)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.blocks[blockerDID] != nil {
		delete(s.blocks[blockerDID], blockedDID)
	}
	s.mu.Unlock()

	return nil
}

func (s *Store) IsBlocked(actorDID, targetDID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check both directions
	if s.blocks[targetDID] != nil && s.blocks[targetDID][actorDID] {
		return true // target blocked the actor
	}
	if s.blocks[actorDID] != nil && s.blocks[actorDID][targetDID] {
		return true // actor blocked the target
	}
	return false
}

func (s *Store) GetStats() (tokenCount int, blockCount int, didCount int) {
	s.db.QueryRow("SELECT COUNT(*) FROM push_tokens").Scan(&tokenCount)
	s.db.QueryRow("SELECT COUNT(*) FROM blocks").Scan(&blockCount)
	s.mu.RLock()
	didCount = len(s.registeredDIDs)
	s.mu.RUnlock()
	return
}

func (s *Store) AddVerification(verifierDID, subjectDID, rkey string) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO verifications (verifier_did, subject_did, rkey) VALUES (?, ?, ?)",
		verifierDID, subjectDID, rkey,
	)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.verificationsByRKey[verifierDID] == nil {
		s.verificationsByRKey[verifierDID] = make(map[string]string)
	}
	s.verificationsByRKey[verifierDID][rkey] = subjectDID
	s.mu.Unlock()

	return nil
}

// RemoveVerificationByRKey removes a verification by verifier DID and rkey.
// Returns the subject DID if found, or empty string if not found.
func (s *Store) RemoveVerificationByRKey(verifierDID, rkey string) (string, error) {
	s.mu.RLock()
	subjectDID := ""
	if s.verificationsByRKey[verifierDID] != nil {
		subjectDID = s.verificationsByRKey[verifierDID][rkey]
	}
	s.mu.RUnlock()

	if subjectDID == "" {
		return "", nil
	}

	_, err := s.db.Exec(
		"DELETE FROM verifications WHERE verifier_did = ? AND rkey = ?",
		verifierDID, rkey,
	)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	if s.verificationsByRKey[verifierDID] != nil {
		delete(s.verificationsByRKey[verifierDID], rkey)
	}
	s.mu.Unlock()

	return subjectDID, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
