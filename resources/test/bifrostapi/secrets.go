// Package bifrostapi has helpers for the integration tests of Bifrost. It has
// the random secret helper and a small client for the Bifrost HTTP API.
package bifrostapi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SecretBytes is the number of random bytes in each secret value.
const SecretBytes = 32

// RandomSecret returns a new secret value. The value is the hex encoding of
// SecretBytes random bytes from crypto/rand. The tests make each secret value
// with this function, so the Go code has no literal secret value.
func RandomSecret() (string, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("bifrostapi: random secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Secrets are all secret values of one test run. Each value is random.
type Secrets struct {
	AdminUser     string
	AdminPassword string
	SetupToken    string
	EncryptionKey string
	// PGAdminPassword is the password of the PostgreSQL superuser.
	PGAdminPassword string
	// PGBifrostPassword is the password of the PostgreSQL role bifrost.
	PGBifrostPassword string
	OpenAIKey         string
	// TokenA and TokenB are two valid per-call tokens of the test MCP server.
	TokenA string
	TokenB string
	// TokenBad is a token that the test MCP server rejects.
	TokenBad string
}

// NewSecrets makes a new set of random secrets.
func NewSecrets() (Secrets, error) {
	var s Secrets
	fields := []*string{
		&s.AdminPassword, &s.SetupToken, &s.EncryptionKey, &s.PGAdminPassword,
		&s.PGBifrostPassword, &s.OpenAIKey, &s.TokenA, &s.TokenB, &s.TokenBad,
	}
	for _, f := range fields {
		v, err := RandomSecret()
		if err != nil {
			return Secrets{}, err
		}
		*f = v
	}
	s.AdminUser = "spike-admin"
	return s, nil
}

// MustRandomSecret is like RandomSecret. It panics on an error. The random
// source of the operating system does not fail in normal use.
func MustRandomSecret() string {
	s, err := RandomSecret()
	if err != nil {
		panic(err)
	}
	return s
}
