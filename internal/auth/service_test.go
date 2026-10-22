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
	if _, err := service.Bootstrap(t.Context(), "correct horse battery staple"); err != nil {
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

func TestBootstrapRotatesChangedPasswordAndRevokesSessions(t *testing.T) {
	t.Parallel()

	database, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "auth.db"), "Europe/Vienna")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	service := New(database, time.Hour)
	if _, err := service.Bootstrap(t.Context(), "original password value"); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	token, _, err := service.Login(t.Context(), "admin", "original password value")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if rotated, err := service.Bootstrap(t.Context(), "original password value"); err != nil || rotated {
		t.Fatalf("Bootstrap(unchanged) = %t, %v; want false, nil", rotated, err)
	}
	if valid, err := service.Valid(t.Context(), token); err != nil || !valid {
		t.Fatalf("Valid(after unchanged bootstrap) = %t, %v", valid, err)
	}

	if rotated, err := service.Bootstrap(t.Context(), "rotated password value"); err != nil || !rotated {
		t.Fatalf("Bootstrap(rotated) = %t, %v; want true, nil", rotated, err)
	}
	if valid, err := service.Valid(t.Context(), token); err != nil || valid {
		t.Errorf("Valid(after rotation) = %t, %v; want revoked", valid, err)
	}
	if _, _, err := service.Login(t.Context(), "admin", "original password value"); err != ErrInvalidCredentials {
		t.Errorf("Login(old password) error = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := service.Login(t.Context(), "admin", "rotated password value"); err != nil {
		t.Errorf("Login(new password) error = %v", err)
	}
}

func TestSessionIdleTimeoutAndLogoutAll(t *testing.T) {
	t.Parallel()

	database, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "auth.db"), "Europe/Vienna")
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	now := time.Now()
	service := New(database, 12*time.Hour).WithIdleTimeout(time.Hour)
	service.now = func() time.Time { return now }
	if _, err := service.Bootstrap(t.Context(), "correct horse battery staple"); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	token, _, err := service.Login(t.Context(), "admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	now = now.Add(50 * time.Minute)
	if valid, err := service.Valid(t.Context(), token); err != nil || !valid {
		t.Fatalf("Valid(active) = %t, %v", valid, err)
	}
	now = now.Add(50 * time.Minute)
	if valid, err := service.Valid(t.Context(), token); err != nil || !valid {
		t.Fatalf("Valid(activity extended idle deadline) = %t, %v", valid, err)
	}
	now = now.Add(61 * time.Minute)
	if valid, err := service.Valid(t.Context(), token); err != nil || valid {
		t.Fatalf("Valid(idle) = %t, %v; want expired", valid, err)
	}

	second, _, err := service.Login(t.Context(), "admin", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if err := service.LogoutAll(t.Context()); err != nil {
		t.Fatalf("LogoutAll() error = %v", err)
	}
	if valid, err := service.Valid(t.Context(), second); err != nil || valid {
		t.Errorf("Valid(after LogoutAll) = %t, %v", valid, err)
	}
}
