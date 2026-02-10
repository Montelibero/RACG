package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type Claims struct {
	SessionID string
	ClientID  string
	ExpiresAt time.Time
}

type tokenRecord struct {
	claims Claims
}

type TokenManager struct {
	mu     sync.Mutex
	clock  Clock
	tokens map[string]tokenRecord
}

func NewTokenManager(clk Clock) *TokenManager {
	if clk == nil {
		clk = RealClock{}
	}
	return &TokenManager{clock: clk, tokens: map[string]tokenRecord{}}
}

func (m *TokenManager) Issue(sessionID, clientID string, ttl time.Duration) (token string, expiresAt time.Time) {
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	exp := m.clock.Now().Add(ttl)

	// 32 bytes => 43 chars base64url no padding.
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	tok := base64.RawURLEncoding.EncodeToString(buf)

	m.mu.Lock()
	m.tokens[tok] = tokenRecord{claims: Claims{SessionID: sessionID, ClientID: clientID, ExpiresAt: exp}}
	m.mu.Unlock()

	return tok, exp
}

func (m *TokenManager) Verify(token string) (Claims, error) {
	m.mu.Lock()
	rec, ok := m.tokens[token]
	if !ok {
		m.mu.Unlock()
		return Claims{}, ErrUnauthorized
	}
	// Lazy cleanup on verify.
	if m.clock.Now().After(rec.claims.ExpiresAt) {
		delete(m.tokens, token)
		m.mu.Unlock()
		return Claims{}, ErrSessionExpired
	}
	m.mu.Unlock()
	return rec.claims, nil
}
