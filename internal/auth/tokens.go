package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

type Claims struct {
	SessionID string
	ClientID  string
	ExpiresAt time.Time
}

// tokenRecord keeps the per-token TTL so Verify can slide the expiry.
// ttl <= 0 means the token never expires.
type tokenRecord struct {
	claims Claims
	ttl    time.Duration
}

// TokenManager keeps session tokens in memory, keyed by HashToken.
//
// Persistence is write-through via a single OnChange sink (chosen over
// store calls at each caller so Issue/Verify-slide/Revoke stay
// persistence-agnostic): the manager hashes raw tokens with HashToken
// and reports every insert/update/delete, so the sink never sees raw
// secrets. The server registers one sink that mirrors records into
// SQLite and replays them after restart via Restore.
type TokenManager struct {
	mu       sync.Mutex
	clock    Clock
	tokens   map[string]tokenRecord
	onChange func(hash string, claims Claims, deleted bool)
}

func NewTokenManager(clk Clock) *TokenManager {
	if clk == nil {
		clk = RealClock{}
	}
	return &TokenManager{clock: clk, tokens: map[string]tokenRecord{}}
}

// HashToken returns the hex SHA-256 of a raw bearer token. Tokens are
// persisted only in this hashed form.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// OnChange registers the single persistence sink. The sink receives the
// token hash (never the raw token); deleted=true means the record was
// removed and must be dropped from the store. The callback runs while
// the manager lock is held and must not call back into the manager.
func (m *TokenManager) OnChange(fn func(hash string, claims Claims, deleted bool)) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

// Restore re-inserts an already-persisted record keyed by its
// precomputed hash (HashToken of the raw token). It fires no callback:
// the record is by definition already in the store. Restored records
// carry no TTL, so they no longer slide; they stay valid until the
// restored expiry.
func (m *TokenManager) Restore(hash string, claims Claims) {
	m.mu.Lock()
	m.tokens[hash] = tokenRecord{claims: claims}
	m.mu.Unlock()
}

// Issue mints a token for the session. ttl <= 0 means the token never
// expires (zero ExpiresAt).
func (m *TokenManager) Issue(sessionID, clientID string, ttl time.Duration) (string, time.Time) {
	if ttl < 0 {
		ttl = 0
	}
	var exp time.Time
	if ttl > 0 {
		exp = m.clock.Now().Add(ttl)
	}

	// 32 bytes => 43 chars base64url no padding.
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	tok := base64.RawURLEncoding.EncodeToString(buf)

	claims := Claims{SessionID: sessionID, ClientID: clientID, ExpiresAt: exp}
	hash := HashToken(tok)

	m.mu.Lock()
	m.tokens[hash] = tokenRecord{claims: claims, ttl: ttl}
	fn := m.onChange
	m.mu.Unlock()

	if fn != nil {
		fn(hash, claims, false)
	}
	return tok, exp
}

// Verify validates the token. A token with a zero ExpiresAt never
// expires; otherwise every successful verify slides the deadline out by
// the token's own TTL (only tokens issued with ttl > 0 slide).
func (m *TokenManager) Verify(token string) (Claims, error) {
	hash := HashToken(token)

	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.tokens[hash]
	if !ok {
		return Claims{}, ErrUnauthorized
	}
	now := m.clock.Now()
	if !rec.claims.ExpiresAt.IsZero() && now.After(rec.claims.ExpiresAt) {
		// Lazy cleanup on verify.
		delete(m.tokens, hash)
		if fn := m.onChange; fn != nil {
			fn(hash, rec.claims, true)
		}
		return Claims{}, ErrSessionExpired
	}
	if rec.ttl > 0 {
		rec.claims.ExpiresAt = now.Add(rec.ttl)
		m.tokens[hash] = rec
		if fn := m.onChange; fn != nil {
			fn(hash, rec.claims, false)
		}
	}
	return rec.claims, nil
}

// Extend moves a valid token's expiry to now+ttl (clears it when
// ttl <= 0), re-arms its sliding TTL and returns the new expiry.
// Unknown tokens fail with ErrUnauthorized, expired ones with
// ErrSessionExpired.
func (m *TokenManager) Extend(token string, ttl time.Duration) (time.Time, error) {
	if ttl < 0 {
		ttl = 0
	}
	hash := HashToken(token)

	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.tokens[hash]
	if !ok {
		return time.Time{}, ErrUnauthorized
	}
	now := m.clock.Now()
	if !rec.claims.ExpiresAt.IsZero() && now.After(rec.claims.ExpiresAt) {
		delete(m.tokens, hash)
		if fn := m.onChange; fn != nil {
			fn(hash, rec.claims, true)
		}
		return time.Time{}, ErrSessionExpired
	}
	rec.ttl = ttl
	if ttl == 0 {
		rec.claims.ExpiresAt = time.Time{}
	} else {
		rec.claims.ExpiresAt = now.Add(ttl)
	}
	m.tokens[hash] = rec
	if fn := m.onChange; fn != nil {
		fn(hash, rec.claims, false)
	}
	return rec.claims.ExpiresAt, nil
}

// Revoke deletes one token and reports whether it existed.
func (m *TokenManager) Revoke(token string) bool {
	hash := HashToken(token)

	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.tokens[hash]
	if !ok {
		return false
	}
	delete(m.tokens, hash)
	if fn := m.onChange; fn != nil {
		fn(hash, rec.claims, true)
	}
	return true
}

// RevokeSession deletes every token of the session and returns how many
// were dropped.
func (m *TokenManager) RevokeSession(sessionID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	n := 0
	for hash, rec := range m.tokens {
		if rec.claims.SessionID != sessionID {
			continue
		}
		delete(m.tokens, hash)
		n++
		if fn := m.onChange; fn != nil {
			fn(hash, rec.claims, true)
		}
	}
	return n
}

// ListSessions returns the claims of every tracked token, including
// expired ones that have not been verified (and thus collected) yet.
func (m *TokenManager) ListSessions() []Claims {
	m.mu.Lock()
	out := make([]Claims, 0, len(m.tokens))
	for _, rec := range m.tokens {
		out = append(out, rec.claims)
	}
	m.mu.Unlock()
	return out
}

// ExtendSession slides every token of the session to now+ttl (clears
// the expiry when ttl <= 0) and returns the new expiry. Unknown
// sessions fail with ErrSessionNotFound.
func (m *TokenManager) ExtendSession(sessionID string, ttl time.Duration) (time.Time, error) {
	if ttl < 0 {
		ttl = 0
	}
	var exp time.Time
	if ttl > 0 {
		exp = m.clock.Now().Add(ttl)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	n := 0
	for hash, rec := range m.tokens {
		if rec.claims.SessionID != sessionID {
			continue
		}
		rec.ttl = ttl
		rec.claims.ExpiresAt = exp
		m.tokens[hash] = rec
		n++
		if fn := m.onChange; fn != nil {
			fn(hash, rec.claims, false)
		}
	}
	if n == 0 {
		return time.Time{}, ErrSessionNotFound
	}
	return exp, nil
}
