package chat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("12", now); got != 12*time.Second {
		t.Fatalf("seconds retry-after=%v", got)
	}
	date := now.Add(30 * time.Second).Format(http.TimeFormat)
	if got := parseRetryAfter(date, now); got != 30*time.Second {
		t.Fatalf("date retry-after=%v", got)
	}
	if got := parseRetryAfter("invalid", now); got != 0 {
		t.Fatalf("invalid retry-after=%v", got)
	}
}

func TestClientCallsChatServiceDirectly(t *testing.T) {
	var requestPath string
	var authorization string
	var proxyHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		authorization = r.Header.Get("Authorization")
		proxyHeader = r.Header.Get("atproto-proxy")
		_, _ = w.Write([]byte(`{"cursor":"next","logs":[]}`))
	}))
	t.Cleanup(server.Close)

	client := NewClient(server.Client())
	client.serviceURL = server.URL
	page, err := client.GetLog(context.Background(), "https://pds.example", "access-token", "")
	if err != nil {
		t.Fatal(err)
	}
	if page.Cursor != "next" || requestPath != "/xrpc/chat.bsky.convo.getLog" {
		t.Fatalf("unexpected chat response or path: cursor=%q path=%q", page.Cursor, requestPath)
	}
	if authorization != "Bearer access-token" {
		t.Fatalf("unexpected authorization header: %q", authorization)
	}
	if proxyHeader != "" {
		t.Fatalf("direct chat request included atproto-proxy: %q", proxyHeader)
	}
}
