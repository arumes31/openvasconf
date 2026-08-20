package auth

import (
	"path/filepath"
	"testing"
	"time"

	"openvasconf/internal/store"
)

func TestServiceLifecycle(t *testing.T) {
	t.Parallel()

	database, err := store.Open(
		t.Context(),
		filepath.Join(t.TempDir(), "auth.db"),
		"Europe/Vienna",
	)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	service := New(database, time.Hour)
	if err := service.Bootstrap(t.Context(), "correct horse battery staple"); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if _, _, err := service.Login(t.Context(), "admin", "wrong password"); err != ErrInvalidCredentials {
		t.Fatalf("Login(wrong) error = %v, want ErrInvalidCredentials", err)
	}
	token, expiresAt, err := service.Login(
		t.Context(),
		"admin",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if token == "" || !expiresAt.After(time.Now()) {
		t.Fatalf("token = %q, expiresAt = %v", token, expiresAt)
	}
	valid, err := service.Valid(t.Context(), token)
	if err != nil || !valid {
		t.Fatalf("Valid() = %t, %v", valid, err)
	}
	if err := service.Logout(t.Context(), token); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	valid, err = service.Valid(t.Context(), token)
	if err != nil || valid {
		t.Fatalf("Valid(after logout) = %t, %v", valid, err)
	}
}
