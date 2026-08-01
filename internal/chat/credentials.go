package chat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
)

type credentials struct {
	AppPassword string `json:"appPassword"`
	AccessJWT   string `json:"accessJwt,omitempty"`
	RefreshJWT  string `json:"refreshJwt,omitempty"`
}

type credentialCipher struct {
	aead cipher.AEAD
}

func newCredentialCipher(key []byte) (*credentialCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("DM credential encryption key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &credentialCipher{aead: aead}, nil
}

func (c *credentialCipher) seal(value credentials) ([]byte, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode credentials: %w", err)
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("create credential nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *credentialCipher) open(ciphertext []byte) (credentials, error) {
	if len(ciphertext) < c.aead.NonceSize() {
		return credentials{}, fmt.Errorf("encrypted credentials are truncated")
	}
	nonce := ciphertext[:c.aead.NonceSize()]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext[c.aead.NonceSize():], nil)
	if err != nil {
		return credentials{}, fmt.Errorf("decrypt credentials")
	}
	var value credentials
	if err := json.Unmarshal(plaintext, &value); err != nil {
		return credentials{}, fmt.Errorf("decode credentials")
	}
	return value, nil
}
