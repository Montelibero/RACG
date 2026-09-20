package store

import (
	"context"
	"time"
)

// AuthToken is a persisted bearer-token record. TokenHash is the hex
// SHA-256 of the raw token; raw tokens are never stored. A zero
// ExpiresAt (persisted as "") means the token never expires.
type AuthToken struct {
	TokenHash string
	SessionID string
	ClientID  string
	ExpiresAt time.Time
}

func (s *Store) UpsertAuthToken(ctx context.Context, tokenHash, sessionID, clientID string, expiresAt time.Time) error {
	exp := ""
	if !expiresAt.IsZero() {
		exp = expiresAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO auth_tokens (token_hash, session_id, client_id, expires_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(token_hash) DO UPDATE SET
  session_id = excluded.session_id,
  client_id = excluded.client_id,
  expires_at = excluded.expires_at`,
		tokenHash, sessionID, clientID, exp)
	return err
}

func (s *Store) ListAuthTokens(ctx context.Context) ([]AuthToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token_hash, session_id, client_id, expires_at FROM auth_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuthToken
	for rows.Next() {
		var t AuthToken
		var exp string
		if err := rows.Scan(&t.TokenHash, &t.SessionID, &t.ClientID, &exp); err != nil {
			return nil, err
		}
		if exp != "" {
			if t.ExpiresAt, err = time.Parse(time.RFC3339Nano, exp); err != nil {
				return nil, err
			}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAuthToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_tokens WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) DeleteAuthTokensBySession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_tokens WHERE session_id = ?`, sessionID)
	return err
}
