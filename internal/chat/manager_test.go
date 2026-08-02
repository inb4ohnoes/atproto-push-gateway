package chat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dracoblue/atproto-push-gateway/internal/store"
)

func testJWT(exp time.Time) string {
	payload, _ := json.Marshal(map[string]int64{"exp": exp.Unix()})
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func newTestManager(t *testing.T, handler http.Handler) (*Manager, *store.Store, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	s, err := store.New(filepath.Join(t.TempDir(), "chat.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	manager, err := NewManager(s, []byte("0123456789abcdef0123456789abcdef"), server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	manager.chatServiceURL = server.URL
	return manager, s, server
}

func TestEnrollEncryptsCredentialsAndChecksChatScope(t *testing.T) {
	var sawChatService bool
	var sawProxy bool
	var sawUnexpectedQuery bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			_ = json.NewEncoder(w).Encode(session{DID: "did:plc:alice", AccessJWT: testJWT(time.Now().Add(time.Hour)), RefreshJWT: "refresh-secret"})
		case "/xrpc/chat.bsky.convo.getLog":
			sawChatService = true
			sawProxy = r.Header.Get("atproto-proxy") != ""
			sawUnexpectedQuery = r.URL.RawQuery != ""
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	manager, s, server := newTestManager(t, handler)
	if err := manager.Enroll(context.Background(), "did:plc:alice", "password-secret", server.URL); err != nil {
		t.Fatal(err)
	}
	if !sawChatService {
		t.Fatal("chat scope check did not reach the configured chat service")
	}
	if sawProxy {
		t.Fatal("direct chat service request unexpectedly used an atproto-proxy header")
	}
	if sawUnexpectedQuery {
		t.Fatal("chat scope check sent parameters that getLog does not support")
	}
	enrollment, found, err := s.GetDMEnrollment("did:plc:alice")
	if err != nil || !found {
		t.Fatalf("missing enrollment: found=%v err=%v", found, err)
	}
	stored := string(enrollment.EncryptedCredentials)
	if strings.Contains(stored, "password-secret") || strings.Contains(stored, "refresh-secret") {
		t.Fatal("credential material was stored in plaintext")
	}
}

func TestNotificationTextEncryptionRoundTrip(t *testing.T) {
	manager, _, _ := newTestManager(t, http.NotFoundHandler())
	plaintext := "private message body"
	ciphertext, err := manager.EncryptNotificationText(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), plaintext) {
		t.Fatal("notification text was not encrypted")
	}
	decrypted, err := manager.DecryptNotificationText(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plaintext {
		t.Fatalf("decrypted %q, want %q", decrypted, plaintext)
	}
}

func TestEnrollDistinguishesPasswordAndDMScopeFailures(t *testing.T) {
	tests := []struct {
		name       string
		createCode int
		chatCode   int
		chatBody   string
		want       error
	}{
		{name: "bad password", createCode: http.StatusUnauthorized, want: ErrBadPassword},
		{name: "missing DM access", createCode: http.StatusOK, chatCode: http.StatusForbidden, want: ErrDMAccess},
		{name: "missing DM access returned as 501", createCode: http.StatusOK, chatCode: http.StatusNotImplemented, chatBody: `{"error":"InvalidToken","message":"Bad token scope"}`, want: ErrDMAccess},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/xrpc/com.atproto.server.createSession" {
					if test.createCode != http.StatusOK {
						w.WriteHeader(test.createCode)
						return
					}
					_ = json.NewEncoder(w).Encode(session{DID: "did:plc:alice", AccessJWT: testJWT(time.Now().Add(time.Hour)), RefreshJWT: "refresh"})
					return
				}
				w.WriteHeader(test.chatCode)
				_, _ = w.Write([]byte(test.chatBody))
			})
			manager, _, server := newTestManager(t, handler)
			err := manager.Enroll(context.Background(), "did:plc:alice", "secret", server.URL)
			if err != test.want {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestEnrollPreservesSafeChatFailureDetailsForDiagnostics(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/xrpc/com.atproto.server.createSession" {
			_ = json.NewEncoder(w).Encode(session{DID: "did:plc:alice", AccessJWT: testJWT(time.Now().Add(time.Hour)), RefreshJWT: "refresh"})
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"error":"AccountFeatureUnavailable","message":"chat migration pending"}`))
	})
	manager, _, server := newTestManager(t, handler)
	err := manager.Enroll(context.Background(), "did:plc:alice", "secret", server.URL)
	if err == nil || err.Error() != "chat access check returned HTTP 501: AccountFeatureUnavailable chat migration pending" {
		t.Fatalf("unexpected diagnostic error: %v", err)
	}
}

func TestAccessTokenFallsBackToCreateAndMarksRevokedCredential(t *testing.T) {
	createCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/xrpc/com.atproto.server.createSession":
			createCalls++
			if createCalls > 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(session{DID: "did:plc:alice", AccessJWT: testJWT(time.Now().Add(-time.Minute)), RefreshJWT: "expired-refresh"})
		case "/xrpc/com.atproto.server.refreshSession":
			w.WriteHeader(http.StatusUnauthorized)
		case "/xrpc/chat.bsky.convo.getLog":
			w.WriteHeader(http.StatusOK)
		}
	})
	manager, s, server := newTestManager(t, handler)
	if err := manager.Enroll(context.Background(), "did:plc:alice", "revoked-password", server.URL); err != nil {
		t.Fatal(err)
	}
	_, _, err := manager.AccessToken(context.Background(), "did:plc:alice")
	if err != ErrNeedsReauth {
		t.Fatalf("got %v, want needs reauth", err)
	}
	enrollment, found, err := s.GetDMEnrollment("did:plc:alice")
	if err != nil || !found || enrollment.State != "needs_reauth" || len(enrollment.EncryptedCredentials) != 0 {
		t.Fatalf("revoked credential was not dropped: %+v found=%v err=%v", enrollment, found, err)
	}
}

func TestRevokeIsIdempotentAndDeletesCursor(t *testing.T) {
	manager, s, _ := newTestManager(t, http.NotFoundHandler())
	if err := s.UpsertDMEnrollment(store.DMEnrollment{ActorDID: "did:plc:alice", PDSHost: "https://example.com", EncryptedCredentials: []byte("x"), State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChatCursor("did:plc:alice", "cursor"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Revoke("did:plc:alice"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Revoke("did:plc:alice"); err != nil {
		t.Fatalf("second revoke failed: %v", err)
	}
	cursor, err := s.GetChatCursor("did:plc:alice")
	if err != nil || cursor != "" {
		t.Fatalf("cursor survived revoke: %q, %v", cursor, err)
	}
}
