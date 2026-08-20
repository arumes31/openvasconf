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
	CreateSession(ctx context.Context, tokenHash string, expiresAt time.Time) error
	SessionValid(ctx context.Context, tokenHash string, now time.Time) (bool, error)
	DeleteSession(ctx context.Context, tokenHash string) error
}

type Service struct {
	store    Store
	lifetime time.Duration
	now      func() time.Time
}

func New(store Store, lifetime time.Duration) *Service {
	return &Service{
		store:    store,
		lifetime: lifetime,
		now:      time.Now,
	}
}

func (s *Service) Bootstrap(ctx context.Context, password string) error {
	_, err := s.store.AdminPasswordHash(ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("checking admin account: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("hashing admin password: %w", err)
	}
	if err := s.store.CreateAdmin(ctx, hash); err != nil {
		return fmt.Errorf("bootstrapping admin account: %w", err)
	}
	return nil
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
	return s.store.SessionValid(ctx, tokenHash(token), s.now())
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.store.DeleteSession(ctx, tokenHash(token))
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
