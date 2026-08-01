package chat

import (
	"net/http"
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
