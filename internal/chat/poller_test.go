package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dracoblue/atproto-push-gateway/internal/push"
	"github.com/dracoblue/atproto-push-gateway/internal/store"
)

type fakeAccessTokenProvider struct {
	marked []string
}

func (f *fakeAccessTokenProvider) AccessToken(context.Context, string) (string, string, error) {
	return "https://pds.example", "access-token", nil
}

func (f *fakeAccessTokenProvider) MarkNeedsReauth(actorDID string) error {
	f.marked = append(f.marked, actorDID)
	return nil
}

func (f *fakeAccessTokenProvider) EncryptNotificationText(text string) ([]byte, error) {
	return append([]byte("encrypted:"), []byte(text)...), nil
}

func (f *fakeAccessTokenProvider) DecryptNotificationText(ciphertext []byte) (string, error) {
	return string(bytes.TrimPrefix(ciphertext, []byte("encrypted:"))), nil
}

type fakeChatAPI struct {
	pages         []LogPage
	cursors       []string
	conversations map[string]Conversation
	preferences   Preferences
	logErr        error
}

func (f *fakeChatAPI) GetLog(_ context.Context, _, _, cursor string) (LogPage, error) {
	f.cursors = append(f.cursors, cursor)
	if f.logErr != nil {
		return LogPage{}, f.logErr
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func (f *fakeChatAPI) GetConversation(_ context.Context, _, _, id string) (Conversation, error) {
	return f.conversations[id], nil
}

func (f *fakeChatAPI) GetPreferences(context.Context, string, string) (Preferences, error) {
	return f.preferences, nil
}

type recordingSender struct {
	notifications []push.Notification
	failures      int
}

type tokenFailureSender struct {
	attempts map[string]int
	failOnce string
}

func (s *tokenFailureSender) Send(notification push.Notification) error {
	s.attempts[notification.Token]++
	if notification.Token == s.failOnce && s.attempts[notification.Token] == 1 {
		return errors.New("temporary push failure")
	}
	return nil
}

func (s *recordingSender) Send(notification push.Notification) error {
	if s.failures > 0 {
		s.failures--
		return errors.New("temporary push failure")
	}
	s.notifications = append(s.notifications, notification)
	return nil
}

func chatEvent(eventType, convoID, messageType, messageID, senderDID, text string, profile Profile) json.RawMessage {
	value := map[string]any{
		"$type":   eventType,
		"convoId": convoID,
		"message": map[string]any{
			"$type":  messageType,
			"id":     messageID,
			"sender": map[string]string{"did": senderDID},
			"text":   text,
		},
		"relatedProfiles": []Profile{profile},
	}
	data, _ := json.Marshal(value)
	return data
}

func directConversation(id, status string, muted bool, members ...Profile) Conversation {
	conversation := Conversation{ID: id, Status: status, Muted: muted, Members: members}
	conversation.Kind.Type = directConversationType
	return conversation
}

func newPollerStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "poller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.RegisterToken("did:plc:me", "ios", "device-token", "app.test"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFindProfileMergesSparseSources(t *testing.T) {
	related := Profile{DID: "did:plc:sender", DisplayName: "Sender"}
	member := Profile{
		DID:    "did:plc:sender",
		Handle: "sender.test",
		Avatar: "https://example.com/avatar.jpg",
	}
	member.Viewer.Following = "at://did:plc:me/app.bsky.graph.follow/1"

	got := findProfile("did:plc:sender", []Profile{related}, []Profile{member})
	if got.DisplayName != "Sender" || got.Handle != "sender.test" || got.Avatar != member.Avatar || got.Viewer.Following != member.Viewer.Following {
		t.Fatalf("profile fields were not merged: %#v", got)
	}
}

func TestPollerResumesFiltersAndDeduplicatesWithPrivateMessageText(t *testing.T) {
	s := newPollerStore(t)
	senderProfile := Profile{DID: "did:plc:sender", Handle: "sender.test", DisplayName: "Sender", Avatar: "https://example.com/avatar.jpg"}
	senderProfile.Viewer.Following = "at://did:plc:me/app.bsky.graph.follow/1"
	api := &fakeChatAPI{
		pages: []LogPage{
			{Cursor: "c1", Logs: []json.RawMessage{chatEvent(logCreateMessageType, "accepted", "chat.bsky.convo.defs#messageView", "old", senderProfile.DID, "old secret", senderProfile)}},
			{Cursor: "c2", Logs: []json.RawMessage{
				chatEvent(logCreateMessageType, "accepted", "chat.bsky.convo.defs#messageView", "m1", senderProfile.DID, "TOP SECRET MESSAGE", senderProfile),
				chatEvent(logCreateMessageType, "accepted", "chat.bsky.convo.defs#messageView", "self", "did:plc:me", "self text", Profile{DID: "did:plc:me"}),
				chatEvent(logCreateMessageType, "accepted", deletedMessageType, "deleted", senderProfile.DID, "deleted text", senderProfile),
				chatEvent("chat.bsky.convo.defs#logAddMember", "accepted", "chat.bsky.convo.defs#systemMessageView", "system", senderProfile.DID, "system text", senderProfile),
				chatEvent(logCreateMessageType, "group", "chat.bsky.convo.defs#messageView", "group-message", senderProfile.DID, "group text", senderProfile),
				chatEvent(logCreateMessageType, "request", "chat.bsky.convo.defs#messageView", "request-message", senderProfile.DID, "request text", senderProfile),
			}},
			{Cursor: "c3", Logs: []json.RawMessage{chatEvent(logCreateMessageType, "accepted", "chat.bsky.convo.defs#messageView", "m1", senderProfile.DID, "TOP SECRET MESSAGE", senderProfile)}},
		},
		conversations: map[string]Conversation{
			"accepted": directConversation("accepted", "accepted", false, senderProfile),
			"request":  directConversation("request", "request", false, senderProfile),
			"group": func() Conversation {
				conversation := Conversation{ID: "group", Status: "accepted", Members: []Profile{senderProfile}}
				conversation.Kind.Type = "chat.bsky.convo.defs#groupConvo"
				return conversation
			}(),
		},
		preferences: Preferences{
			Chat:        ChatPreference{Include: "all", Push: true},
			ChatRequest: ChatPreference{Include: "all", Push: false},
		},
	}
	sender := &recordingSender{}
	poller := NewPoller(s, &fakeAccessTokenProvider{}, api, sender)

	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	for range 3 {
		if err := poller.PollOnce(context.Background(), "did:plc:me"); err != nil {
			t.Fatal(err)
		}
	}
	if len(sender.notifications) != 1 {
		t.Fatalf("got %d notifications, want 1", len(sender.notifications))
	}
	notification := sender.notifications[0]
	if notification.Data["reason"] != "chat" || notification.Data["convoId"] != "accepted" || notification.Data["messageId"] != "m1" {
		t.Fatalf("unexpected payload: %#v", notification.Data)
	}
	if _, exists := notification.Data["uri"]; exists {
		t.Fatal("chat payload must not invent an AT URI")
	}
	if notification.Title != "💬 Sender (@sender.test)" || notification.Body != "TOP SECRET MESSAGE" {
		t.Fatalf("unexpected notification presentation: title=%q body=%q", notification.Title, notification.Body)
	}
	encodedData, _ := json.Marshal(notification.Data)
	if bytes.Contains(encodedData, []byte("TOP SECRET MESSAGE")) || bytes.Contains(logs.Bytes(), []byte("TOP SECRET MESSAGE")) {
		t.Fatal("message text reached custom payload data or a log")
	}
	pending, err := s.GetPendingChatMessages("did:plc:me")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatal("delivered message body was retained")
	}
	if got := api.cursors; len(got) != 3 || got[0] != "" || got[1] != "c1" || got[2] != "c2" {
		t.Fatalf("unexpected cursor sequence: %#v", got)
	}
}

func TestPollerPersistsPendingBeforePushAndResumesWithoutLoss(t *testing.T) {
	s := newPollerStore(t)
	if err := s.SetChatCursor("did:plc:me", "c1"); err != nil {
		t.Fatal(err)
	}
	profile := Profile{DID: "did:plc:sender", Handle: "sender.test"}
	api := &fakeChatAPI{
		pages: []LogPage{
			{Cursor: "c2", Logs: []json.RawMessage{chatEvent(logCreateMessageType, "convo", "chat.bsky.convo.defs#messageView", "m1", profile.DID, "private", profile)}},
			{Cursor: "c3"},
		},
		conversations: map[string]Conversation{"convo": directConversation("convo", "accepted", false, profile)},
		preferences:   Preferences{Chat: ChatPreference{Include: "all", Push: true}},
	}
	sender := &recordingSender{failures: 1}
	poller := NewPoller(s, &fakeAccessTokenProvider{}, api, sender)
	if err := poller.PollOnce(context.Background(), "did:plc:me"); err == nil {
		t.Fatal("expected push failure")
	}
	cursor, _ := s.GetChatCursor("did:plc:me")
	if cursor != "c2" {
		t.Fatalf("cursor was not committed with pending message: %q", cursor)
	}
	if err := poller.PollOnce(context.Background(), "did:plc:me"); err != nil {
		t.Fatal(err)
	}
	if len(sender.notifications) != 1 || sender.notifications[0].Data["messageId"] != "m1" {
		t.Fatalf("pending message was not resumed: %#v", sender.notifications)
	}
}

func TestPollerDoesNotRedeliverSuccessfulDeviceWhenAnotherDeviceRetries(t *testing.T) {
	s := newPollerStore(t)
	if err := s.RegisterToken("did:plc:me", "ios", "second-device", "app.test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetChatCursor("did:plc:me", "c1"); err != nil {
		t.Fatal(err)
	}
	profile := Profile{DID: "did:plc:sender"}
	api := &fakeChatAPI{
		pages: []LogPage{
			{Cursor: "c2", Logs: []json.RawMessage{chatEvent(logCreateMessageType, "convo", "chat.bsky.convo.defs#messageView", "m1", profile.DID, "private", profile)}},
			{Cursor: "c3"},
		},
		conversations: map[string]Conversation{"convo": directConversation("convo", "accepted", false, profile)},
		preferences:   Preferences{Chat: ChatPreference{Include: "all", Push: true}},
	}
	sender := &tokenFailureSender{attempts: make(map[string]int), failOnce: "second-device"}
	poller := NewPoller(s, &fakeAccessTokenProvider{}, api, sender)
	if err := poller.PollOnce(context.Background(), "did:plc:me"); err == nil {
		t.Fatal("expected one device delivery to fail")
	}
	if err := poller.PollOnce(context.Background(), "did:plc:me"); err != nil {
		t.Fatal(err)
	}
	if sender.attempts["device-token"] != 1 || sender.attempts["second-device"] != 2 {
		t.Fatalf("unexpected per-device attempts: %#v", sender.attempts)
	}
}

func TestPollerMarksUnauthorizedEnrollmentForReauth(t *testing.T) {
	s := newPollerStore(t)
	credentials := &fakeAccessTokenProvider{}
	api := &fakeChatAPI{logErr: &HTTPStatusError{StatusCode: 401}}
	poller := NewPoller(s, credentials, api, &recordingSender{})
	if err := poller.PollOnce(context.Background(), "did:plc:me"); err != ErrNeedsReauth {
		t.Fatalf("got %v", err)
	}
	if len(credentials.marked) != 1 || credentials.marked[0] != "did:plc:me" {
		t.Fatalf("credential was not marked for reauth: %#v", credentials.marked)
	}
}

func TestNextPollDelayBackoffAndRateLimit(t *testing.T) {
	normal := 15 * time.Second
	if got := nextPollDelay(time.Minute, normal, nil); got != normal {
		t.Fatalf("success delay=%v", got)
	}
	if got := nextPollDelay(0, normal, errors.New("temporary")); got != time.Second {
		t.Fatalf("initial backoff=%v", got)
	}
	if got := nextPollDelay(40*time.Second, normal, errors.New("temporary")); got != time.Minute {
		t.Fatalf("capped backoff=%v", got)
	}
	if got := nextPollDelay(0, normal, &HTTPStatusError{StatusCode: 429, RetryAfter: 37 * time.Second}); got != 37*time.Second {
		t.Fatalf("retry-after delay=%v", got)
	}
}

func TestChatNotificationBodySanitizesAndTruncates(t *testing.T) {
	if got := chatNotificationBody("  private\n\tmessage  "); got != "private message" {
		t.Fatalf("sanitized body=%q", got)
	}
	long := strings.Repeat("🙂", 301)
	got := chatNotificationBody(long)
	if len([]rune(got)) != 301 || !strings.HasSuffix(got, "…") {
		t.Fatalf("body was not safely truncated: rune count=%d", len([]rune(got)))
	}
}
