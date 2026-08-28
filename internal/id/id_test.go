package id

import (
	"encoding/hex"
	"regexp"
	"testing"
)

func TestNewReturnsRFC4122Version4ID(t *testing.T) {
	t.Parallel()

	first, err := New()
	if err != nil {
		t.Fatal(err)
	}
	second, err := New()
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !pattern.MatchString(first) || !pattern.MatchString(second) {
		t.Fatalf("generated IDs = %q, %q", first, second)
	}
	if first == second {
		t.Fatal("two generated IDs are equal")
	}
}

func TestTokenValidatesSizeAndReturnsHex(t *testing.T) {
	t.Parallel()

	if _, err := Token(15); err == nil {
		t.Fatal("Token(15) error = nil")
	}
	token, err := Token(24)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not hex: %v", err)
	}
	if len(decoded) != 24 {
		t.Errorf("decoded token length = %d, want 24", len(decoded))
	}
}
