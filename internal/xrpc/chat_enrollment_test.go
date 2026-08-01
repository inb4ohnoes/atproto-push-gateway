package xrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dracoblue/atproto-push-gateway/internal/chat"
)

type fakeChatEnrollment struct {
	enrollErr error
	revokes   int
}

func (f *fakeChatEnrollment) Enroll(context.Context, string, string, string) error {
	return f.enrollErr
}
func (f *fakeChatEnrollment) Revoke(string) error          { f.revokes++; return nil }
func (f *fakeChatEnrollment) State(string) (string, error) { return "active", nil }

func TestEnrollChatBindsBodyDIDToAuthenticatedActor(t *testing.T) {
	h, _ := newTestHandler(t)
	h.SetChatEnrollmentManager(&fakeChatEnrollment{})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, "did:web:push.example.org")
	body, _ := json.Marshal(enrollChatRequest{DID: "did:plc:bob", AppPassword: "secret", PDSHost: "https://bsky.social"})
	request := httptest.NewRequest(http.MethodPost, "/xrpc/"+lexiconEnrollChat, bytes.NewReader(body))
	request.Header.Set("X-Actor-DID", "did:plc:alice")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", response.Code)
	}
}

func TestEnrollChatMapsCredentialFailures(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{chat.ErrBadPassword, http.StatusUnauthorized, "invalid_app_password"},
		{chat.ErrDMAccess, http.StatusForbidden, "dm_access_required"},
		{errors.New("upstream"), http.StatusBadGateway, "enrollment_failed"},
	}
	for _, test := range tests {
		h, _ := newTestHandler(t)
		h.SetChatEnrollmentManager(&fakeChatEnrollment{enrollErr: test.err})
		mux := http.NewServeMux()
		h.RegisterRoutes(mux, "did:web:push.example.org")
		body, _ := json.Marshal(enrollChatRequest{DID: "did:plc:alice", AppPassword: "never-echo-me", PDSHost: "https://bsky.social"})
		request := httptest.NewRequest(http.MethodPost, "/xrpc/"+lexiconEnrollChat, bytes.NewReader(body))
		request.Header.Set("X-Actor-DID", "did:plc:alice")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != test.status || !bytes.Contains(response.Body.Bytes(), []byte(test.code)) || bytes.Contains(response.Body.Bytes(), []byte("never-echo-me")) {
			t.Fatalf("unexpected response: status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestRevokeChatIsIdempotent(t *testing.T) {
	h, _ := newTestHandler(t)
	fake := &fakeChatEnrollment{}
	h.SetChatEnrollmentManager(fake)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, "did:web:push.example.org")
	for range 2 {
		request := httptest.NewRequest(http.MethodPost, "/xrpc/"+lexiconRevokeChat, nil)
		request.Header.Set("X-Actor-DID", "did:plc:alice")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("got %d", response.Code)
		}
	}
	if fake.revokes != 2 {
		t.Fatalf("got %d revoke calls", fake.revokes)
	}
}
