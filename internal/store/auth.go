package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (s *Store) AdminPasswordHash(ctx context.Context) ([]byte, error) {
	var hash []byte
	err := s.db.QueryRowContext(
		ctx,
		"SELECT password_hash FROM admins WHERE singleton = 1",
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying admin password: %w", err)
	}
	return hash, nil
}

func (s *Store) CreateAdmin(ctx context.Context, passwordHash []byte) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admins(singleton, username, password_hash, updated_at)
		VALUES(1, 'admin', ?, ?)
		ON CONFLICT(singleton) DO NOTHING`,
		passwordHash,
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("creating admin: %w", err)
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions(token_hash, expires_at, created_at) VALUES(?, ?, ?)`,
		tokenHash,
		expiresAt.UTC().Format(time.RFC3339Nano),
		nowText(),
	)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}
	return nil
}

func (s *Store) SessionValid(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	var expiresAt string
	err := s.db.QueryRowContext(
		ctx,
		"SELECT expires_at FROM sessions WHERE token_hash = ?",
		tokenHash,
	).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("querying session: %w", err)
	}
	expires, err := parseTime(expiresAt)
	if err != nil {
		return false, err
	}
	return now.Before(expires), nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.db.ExecContext(
		ctx,
		"DELETE FROM sessions WHERE token_hash = ?",
		tokenHash,
	); err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(
		ctx,
		"DELETE FROM sessions WHERE expires_at <= ?",
		now.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("deleting expired sessions: %w", err)
	}
	return nil
}
