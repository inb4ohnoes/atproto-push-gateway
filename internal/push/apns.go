package push

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"software.sslmate.com/src/go-pkcs12"
)

// APNsSender sends push notifications directly via Apple Push Notification service.
type APNsSender struct {
	keyID   string
	teamID  string
	key     *ecdsa.PrivateKey
	client  *http.Client
	topic   string // Bundle ID
	sandbox bool   // Use sandbox endpoint (for dev/preview builds)
	baseURL string // overridable in tests; defaults to the APNs production or sandbox host

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewAPNsSender creates a sender from a .p8 key file path.
func NewAPNsSender(keyPath, keyID, teamID, topic string, sandbox bool) (*APNsSender, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read APNs key file: %w", err)
	}
	return newAPNsSenderFromBytes(keyData, keyID, teamID, topic, sandbox)
}

// NewAPNsSenderFromBytes creates a sender from PEM-encoded key bytes.
func NewAPNsSenderFromBytes(keyData []byte, keyID, teamID, topic string, sandbox bool) (*APNsSender, error) {
	return newAPNsSenderFromBytes(keyData, keyID, teamID, topic, sandbox)
}

// NewAPNsSenderFromP12 creates a certificate-authenticated APNs sender from a
// PKCS#12 file. Apple Push Services certificates can be used with both APNs
// endpoints; sandbox selects only the destination endpoint.
func NewAPNsSenderFromP12(path, password, topic string, sandbox bool) (*APNsSender, error) {
	p12Data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read APNs PKCS#12 file: %w", err)
	}
	return NewAPNsSenderFromP12Bytes(p12Data, password, topic, sandbox)
}

// NewAPNsSenderFromP12Bytes creates a certificate-authenticated APNs sender
// from PKCS#12 bytes.
func NewAPNsSenderFromP12Bytes(p12Data []byte, password, topic string, sandbox bool) (*APNsSender, error) {
	privateKey, certificate, caCertificates, err := pkcs12.DecodeChain(p12Data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode APNs PKCS#12 data: %w", err)
	}

	certificateChain := make([][]byte, 0, 1+len(caCertificates))
	certificateChain = append(certificateChain, certificate.Raw)
	for _, caCertificate := range caCertificates {
		certificateChain = append(certificateChain, caCertificate.Raw)
	}

	tlsCertificate := tls.Certificate{
		Certificate: certificateChain,
		PrivateKey:  privateKey,
		Leaf:        certificate,
	}

	baseURL := "https://api.push.apple.com"
	if sandbox {
		baseURL = "https://api.sandbox.push.apple.com"
	}

	return &APNsSender{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig: &tls.Config{
					MinVersion:   tls.VersionTLS12,
					Certificates: []tls.Certificate{tlsCertificate},
				},
			},
		},
		topic:   topic,
		sandbox: sandbox,
		baseURL: baseURL,
	}, nil
}

func newAPNsSenderFromBytes(keyData []byte, keyID, teamID, topic string, sandbox bool) (*APNsSender, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from APNs key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse APNs private key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("APNs key is not an ECDSA key")
	}

	baseURL := "https://api.push.apple.com"
	if sandbox {
		baseURL = "https://api.sandbox.push.apple.com"
	}

	return &APNsSender{
		keyID:   keyID,
		teamID:  teamID,
		key:     ecKey,
		topic:   topic,
		sandbox: sandbox,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// getToken returns a valid APNs JWT, refreshing if needed (tokens are valid for 1 hour).
func (a *APNsSender) getToken() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Reuse token if still valid (refresh 5 minutes before expiry)
	if a.token != "" && time.Now().Before(a.tokenExp.Add(-5*time.Minute)) {
		return a.token, nil
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:   a.teamID,
		IssuedAt: jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = a.keyID

	signedToken, err := token.SignedString(a.key)
	if err != nil {
		return "", fmt.Errorf("failed to sign APNs JWT: %w", err)
	}

	a.token = signedToken
	a.tokenExp = now.Add(1 * time.Hour)

	return a.token, nil
}

type apnsPayload struct {
	APS  apnsAPS           `json:"aps"`
	Data map[string]string `json:"data,omitempty"`
}

type apnsAPS struct {
	Alert          apnsAlert `json:"alert"`
	Sound          string    `json:"sound,omitempty"`
	MutableContent int       `json:"mutable-content,omitempty"`
}

type apnsAlert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func (a *APNsSender) Send(n Notification) error {
	payload := apnsPayload{
		APS: apnsAPS{
			Alert: apnsAlert{
				Title: n.Title,
				Body:  n.Body,
			},
			Sound:          "default",
			MutableContent: 1,
		},
		Data: n.Data,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/3/device/%s", a.baseURL, n.Token)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	if a.key != nil {
		token, err := a.getToken()
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "bearer "+token)
	}
	req.Header.Set("apns-topic", a.topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("APNs request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var errResp struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		// 410 Gone or reason=Unregistered → device token is permanently invalid.
		if resp.StatusCode == 410 || errResp.Reason == "Unregistered" || errResp.Reason == "BadDeviceToken" {
			return fmt.Errorf("%w: APNs %d %s", ErrTokenInvalid, resp.StatusCode, errResp.Reason)
		}
		return fmt.Errorf("APNs returned %d: %s", resp.StatusCode, errResp.Reason)
	}

	log.Printf("[push/apns] sent to %s: %s", tokenForLog(n.Token), n.Data["reason"])
	return nil
}
