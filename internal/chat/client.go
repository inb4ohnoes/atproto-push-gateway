package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type HTTPStatusError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("chat service returned HTTP %d", e.StatusCode)
}

type LogPage struct {
	Cursor string            `json:"cursor"`
	Logs   []json.RawMessage `json:"logs"`
}

type Profile struct {
	DID         string `json:"did"`
	Handle      string `json:"handle"`
	DisplayName string `json:"displayName"`
	Avatar      string `json:"avatar"`
	Viewer      struct {
		Following string `json:"following"`
	} `json:"viewer"`
}

type Conversation struct {
	ID      string    `json:"id"`
	Members []Profile `json:"members"`
	Muted   bool      `json:"muted"`
	Status  string    `json:"status"`
	Kind    struct {
		Type string `json:"$type"`
	} `json:"kind"`
}

type Preferences struct {
	Chat        ChatPreference `json:"chat"`
	ChatRequest ChatPreference `json:"chatRequest"`
}

type ChatPreference struct {
	Include string `json:"include"`
	Push    bool   `json:"push"`
}

type APIClient interface {
	GetLog(context.Context, string, string, string) (LogPage, error)
	GetConversation(context.Context, string, string, string) (Conversation, error)
	GetPreferences(context.Context, string, string) (Preferences, error)
}

type Client struct {
	httpClient *http.Client
	serviceURL string
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{httpClient: httpClient, serviceURL: defaultChatServiceURL}
}

func (c *Client) GetLog(ctx context.Context, _ string, accessJWT, cursor string) (LogPage, error) {
	query := url.Values{}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	var page LogPage
	err := c.get(ctx, c.serviceURL+"/xrpc/chat.bsky.convo.getLog?"+query.Encode(), accessJWT, &page)
	return page, err
}

func (c *Client) GetConversation(ctx context.Context, _ string, accessJWT, conversationID string) (Conversation, error) {
	query := url.Values{"convoId": []string{conversationID}}
	var response struct {
		Conversation Conversation `json:"convo"`
	}
	err := c.get(ctx, c.serviceURL+"/xrpc/chat.bsky.convo.getConvo?"+query.Encode(), accessJWT, &response)
	return response.Conversation, err
}

func (c *Client) GetPreferences(ctx context.Context, _ string, accessJWT string) (Preferences, error) {
	var response struct {
		Preferences Preferences `json:"preferences"`
	}
	err := c.get(ctx, c.serviceURL+"/xrpc/chat.bsky.notification.getPreferences", accessJWT, &response)
	return response.Preferences, err
}

func (c *Client) get(ctx context.Context, endpoint, accessJWT string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+accessJWT)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("chat request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &HTTPStatusError{StatusCode: response.StatusCode, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now())}
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(output); err != nil {
		return fmt.Errorf("decode chat response: %w", err)
	}
	return nil
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil && date.After(now) {
		return date.Sub(now)
	}
	return 0
}
