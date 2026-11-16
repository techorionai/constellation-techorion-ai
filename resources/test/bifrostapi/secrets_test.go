package bifrostapi

import (
	"encoding/hex"
	"testing"
)

// U13: two calls of the random secret helper give two different values. Each
// value has 32 or more random bytes.
func TestU13RandomSecret(t *testing.T) {
	a, err := RandomSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two calls returned the same value")
	}
	for _, v := range []string{a, b} {
		raw, err := hex.DecodeString(v)
		if err != nil {
			t.Fatalf("value is not hex: %v", err)
		}
		if len(raw) < 32 {
			t.Fatalf("value has %d bytes, want 32 or more", len(raw))
		}
	}
}
