package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"openvasconf/internal/id"
	"openvasconf/internal/store"
)

const bcryptCost = 12

var ErrInvalidCredentials = errors.New("auth: invalid credentials")

type Store interface {
	AdminPasswordHash(ctx context.Context) ([]byte, error)
	CreateAdmin(ctx context.Context, passwordHash []byte) error
	ReplaceAdminPassword(ctx context.Context, passwordHash []byte) error
	CreateSession(ctx context.Context, tokenHash string, expiresAt time.Time) error
	SessionActive(ctx context.Context, tokenHash string, now time.Time, idleTimeout time.Duration) (bool, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteAllSessions(ctx context.Context) error
}

type Service struct {
	store       Store
	lifetime    time.Duration
	idleTimeout time.Duration
	now         func() time.Time
}

func New(store Store, lifetime time.Duration) *Service {
	return &Service{
		store:    store,
		lifetime: lifetime,
		now:      time.Now,
	}
}

// WithIdleTimeout ends sessions that have not been used for timeout. Zero
// disables the idle limit and leaves only the absolute session lifetime.
func (s *Service) WithIdleTimeout(timeout time.Duration) *Service {
	s.idleTimeout = timeout
	return s
}

// Bootstrap creates the admin account from the configured password. When the
// account already exists and the configured password no longer matches, the
// password was rotated: the new hash is stored and every session is revoked.
// It reports whether an existing password was rotated.
func (s *Service) Bootstrap(ctx context.Context, password string) (bool, error) {
	current, err := s.store.AdminPasswordHash(ctx)
	if err == nil {
		if bcrypt.CompareHashAndPassword(current, []byte(password)) == nil {
			return false, nil
		}
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
		if hashErr != nil {
			return false, fmt.Errorf("hashing admin password: %w", hashErr)
		}
		if err := s.store.ReplaceAdminPassword(ctx, hash); err != nil {
			return false, fmt.Errorf("rotating admin password: %w", err)
		}
		return true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return false, fmt.Errorf("checking admin account: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return false, fmt.Errorf("hashing admin password: %w", err)
	}
	if err := s.store.CreateAdmin(ctx, hash); err != nil {
		return false, fmt.Errorf("bootstrapping admin account: %w", err)
	}
	return false, nil
}

func (s *Service) Login(ctx context.Context, username, password string) (string, time.Time, error) {
	if username != "admin" {
		return "", time.Time{}, ErrInvalidCredentials
	}
	hash, err := s.store.AdminPasswordHash(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("loading admin account: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return "", time.Time{}, ErrInvalidCredentials
	}
	token, err := id.Token(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := s.now().Add(s.lifetime)
	if err := s.store.CreateSession(ctx, tokenHash(token), expiresAt); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *Service) Valid(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	return s.store.SessionActive(ctx, tokenHash(token), s.now(), s.idleTimeout)
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.store.DeleteSession(ctx, tokenHash(token))
}

// LogoutAll revokes every session, including the caller's.
func (s *Service) LogoutAll(ctx context.Context) error {
	return s.store.DeleteAllSessions(ctx)
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
