package chat

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrBadPassword = errors.New("invalid app password")
	ErrDMAccess    = errors.New("app password lacks direct-message access")
	ErrNeedsReauth = errors.New("app password was revoked")
)

const chatProxy = "did:web:api.bsky.chat#bsky_chat"

type session struct {
	AccessJWT  string `json:"accessJwt"`
	RefreshJWT string `json:"refreshJwt"`
	DID        string `json:"did"`
}

type sessionClient struct {
	httpClient *http.Client
}

func newSessionClient(client *http.Client) *sessionClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &sessionClient{httpClient: client}
}

func validatePDSHost(raw string, devMode bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid pdsHost")
	}
	if u.Scheme != "https" && !(devMode && u.Scheme == "http") {
		return "", fmt.Errorf("pdsHost must use HTTPS")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("pdsHost must be an origin")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func (c *sessionClient) create(ctx context.Context, pdsHost, actorDID, appPassword string) (session, error) {
	body, err := json.Marshal(map[string]string{"identifier": actorDID, "password": appPassword})
	if err != nil {
		return session{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, pdsHost+"/xrpc/com.atproto.server.createSession", bytes.NewReader(body))
	if err != nil {
		return session{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return session{}, fmt.Errorf("create session request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return session{}, ErrBadPassword
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return session{}, fmt.Errorf("create session returned HTTP %d", response.StatusCode)
	}
	return decodeSession(response.Body, actorDID)
}

func (c *sessionClient) refresh(ctx context.Context, pdsHost, actorDID, refreshJWT string) (session, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, pdsHost+"/xrpc/com.atproto.server.refreshSession", nil)
	if err != nil {
		return session{}, err
	}
	request.Header.Set("Authorization", "Bearer "+refreshJWT)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return session{}, fmt.Errorf("refresh session request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return session{}, ErrNeedsReauth
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return session{}, fmt.Errorf("refresh session returned HTTP %d", response.StatusCode)
	}
	return decodeSession(response.Body, actorDID)
}

func decodeSession(reader io.Reader, actorDID string) (session, error) {
	var result session
	if err := json.NewDecoder(io.LimitReader(reader, 64*1024)).Decode(&result); err != nil {
		return session{}, fmt.Errorf("decode session response: %w", err)
	}
	if result.DID != actorDID || result.AccessJWT == "" || result.RefreshJWT == "" {
		return session{}, fmt.Errorf("session identity did not match authenticated actor")
	}
	return result, nil
}

func (c *sessionClient) checkDMAccess(ctx context.Context, pdsHost, accessJWT string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pdsHost+"/xrpc/chat.bsky.convo.getLog?limit=1", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+accessJWT)
	request.Header.Set("atproto-proxy", chatProxy)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("check chat access: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return ErrDMAccess
	}
	if response.StatusCode == http.StatusUnauthorized {
		return ErrNeedsReauth
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("chat access check returned HTTP %d", response.StatusCode)
	}
	return nil
}

func jwtExpiresSoon(token string, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return true
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return true
	}
	return now.Add(time.Minute).Unix() >= claims.Exp
}
