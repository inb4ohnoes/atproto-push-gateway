package chat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dracoblue/atproto-push-gateway/internal/store"
)

type Manager struct {
	store               *store.Store
	cipher              *credentialCipher
	sessions            *sessionClient
	devMode             bool
	onEnrollmentChanged func()
}

func NewManager(s *store.Store, encryptionKey []byte, client *http.Client, devMode bool) (*Manager, error) {
	cipher, err := newCredentialCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	return &Manager{store: s, cipher: cipher, sessions: newSessionClient(client), devMode: devMode}, nil
}

func (m *Manager) SetEnrollmentChangedCallback(callback func()) {
	m.onEnrollmentChanged = callback
}

func (m *Manager) Enroll(ctx context.Context, actorDID, appPassword, rawPDSHost string) error {
	pdsHost, err := validatePDSHost(rawPDSHost, m.devMode)
	if err != nil {
		return err
	}
	created, err := m.sessions.create(ctx, pdsHost, actorDID, appPassword)
	if err != nil {
		return err
	}
	if err := m.sessions.checkDMAccess(ctx, pdsHost, created.AccessJWT); err != nil {
		return err
	}
	ciphertext, err := m.cipher.seal(credentials{
		AppPassword: appPassword,
		AccessJWT:   created.AccessJWT,
		RefreshJWT:  created.RefreshJWT,
	})
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}
	if err := m.store.UpsertDMEnrollment(store.DMEnrollment{
		ActorDID: actorDID, PDSHost: pdsHost, EncryptedCredentials: ciphertext, State: "active",
	}); err != nil {
		return fmt.Errorf("store enrollment: %w", err)
	}
	if m.onEnrollmentChanged != nil {
		m.onEnrollmentChanged()
	}
	return nil
}

func (m *Manager) Revoke(actorDID string) error {
	if err := m.store.RevokeDMEnrollment(actorDID); err != nil {
		return err
	}
	if m.onEnrollmentChanged != nil {
		m.onEnrollmentChanged()
	}
	return nil
}

func (m *Manager) State(actorDID string) (string, error) {
	enrollment, found, err := m.store.GetDMEnrollment(actorDID)
	if err != nil {
		return "", err
	}
	if !found {
		return "not_enrolled", nil
	}
	return enrollment.State, nil
}

func (m *Manager) AccessToken(ctx context.Context, actorDID string) (string, string, error) {
	enrollment, found, err := m.store.GetDMEnrollment(actorDID)
	if err != nil {
		return "", "", err
	}
	if !found || enrollment.State != "active" || len(enrollment.EncryptedCredentials) == 0 {
		return "", "", ErrNeedsReauth
	}
	secret, err := m.cipher.open(enrollment.EncryptedCredentials)
	if err != nil {
		return "", "", err
	}
	if !jwtExpiresSoon(secret.AccessJWT, time.Now()) {
		return enrollment.PDSHost, secret.AccessJWT, nil
	}
	refreshed, err := m.sessions.refresh(ctx, enrollment.PDSHost, actorDID, secret.RefreshJWT)
	if errors.Is(err, ErrNeedsReauth) {
		refreshed, err = m.sessions.create(ctx, enrollment.PDSHost, actorDID, secret.AppPassword)
		if errors.Is(err, ErrBadPassword) {
			_ = m.store.MarkDMEnrollmentNeedsReauth(actorDID)
			if m.onEnrollmentChanged != nil {
				m.onEnrollmentChanged()
			}
			return "", "", ErrNeedsReauth
		}
	}
	if err != nil {
		return "", "", err
	}
	secret.AccessJWT = refreshed.AccessJWT
	secret.RefreshJWT = refreshed.RefreshJWT
	ciphertext, err := m.cipher.seal(secret)
	if err != nil {
		return "", "", err
	}
	enrollment.EncryptedCredentials = ciphertext
	if err := m.store.UpsertDMEnrollment(enrollment); err != nil {
		return "", "", err
	}
	return enrollment.PDSHost, refreshed.AccessJWT, nil
}

func (m *Manager) MarkNeedsReauth(actorDID string) error {
	if err := m.store.MarkDMEnrollmentNeedsReauth(actorDID); err != nil {
		return err
	}
	if m.onEnrollmentChanged != nil {
		m.onEnrollmentChanged()
	}
	return nil
}
