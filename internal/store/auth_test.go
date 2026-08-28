package store

import (
	"errors"
	"testing"
	"time"
)

func TestStoreAdminAndSessionLifecycle(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	database := openTestStore(t)
	if _, err := database.AdminPasswordHash(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AdminPasswordHash() error = %v, want ErrNotFound", err)
	}

	firstHash := []byte("first hash")
	if err := database.CreateAdmin(ctx, firstHash); err != nil {
		t.Fatalf("CreateAdmin() error = %v", err)
	}
	if err := database.CreateAdmin(ctx, []byte("replacement")); err != nil {
		t.Fatalf("CreateAdmin(existing) error = %v", err)
	}
	gotHash, err := database.AdminPasswordHash(ctx)
	if err != nil {
		t.Fatalf("AdminPasswordHash() error = %v", err)
	}
	if string(gotHash) != string(firstHash) {
		t.Errorf("password hash = %q, want %q", gotHash, firstHash)
	}

	now := time.Now().UTC()
	if err := database.CreateSession(ctx, "active", now.Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession(active) error = %v", err)
	}
	if err := database.CreateSession(ctx, "expired", now.Add(-time.Hour)); err != nil {
		t.Fatalf("CreateSession(expired) error = %v", err)
	}
	for _, test := range []struct {
		name  string
		token string
		want  bool
	}{
		{name: "active", token: "active", want: true},
		{name: "expired", token: "expired", want: false},
		{name: "missing", token: "missing", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			valid, err := database.SessionValid(ctx, test.token, now)
			if err != nil {
				t.Fatalf("SessionValid() error = %v", err)
			}
			if valid != test.want {
				t.Errorf("SessionValid() = %t, want %t", valid, test.want)
			}
		})
	}

	if err := database.DeleteExpiredSessions(ctx, now); err != nil {
		t.Fatalf("DeleteExpiredSessions() error = %v", err)
	}
	if valid, err := database.SessionValid(ctx, "expired", now); err != nil || valid {
		t.Errorf("expired session after cleanup = %t, %v", valid, err)
	}
	if err := database.DeleteSession(ctx, "active"); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}
	if valid, err := database.SessionValid(ctx, "active", now); err != nil || valid {
		t.Errorf("deleted session = %t, %v", valid, err)
	}
}

func TestSessionValidRejectsInvalidStoredExpiry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	database := openTestStore(t)
	if _, err := database.db.ExecContext(ctx, `
		INSERT INTO sessions(token_hash, expires_at, created_at)
		VALUES('invalid-time', 'not-a-time', 'not-a-time')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SessionValid(ctx, "invalid-time", time.Now()); err == nil {
		t.Fatal("SessionValid() error = nil, want invalid timestamp error")
	}
}
