package auth

import (
	"testing"
	"time"
)

func TestPairingConsumeOnce(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	p := NewPairing(6, 3*time.Minute, clk)

	code := p.Code()
	if len(code) != 6 {
		t.Fatalf("code len=%d", len(code))
	}

	if err := p.Consume(code); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := p.Consume(code); err != ErrPairingCodeUsed {
		t.Fatalf("expected used, got %v", err)
	}
	if err := p.Consume("WRONG1"); err != ErrPairingCodeInvalid {
		t.Fatalf("expected invalid, got %v", err)
	}
}

func TestPairingExpiry(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	p := NewPairing(6, 2*time.Minute, clk)

	clk.Advance(2*time.Minute + time.Second)
	if err := p.Consume(p.Code()); err != ErrPairingCodeExpired {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestPairingRegenerate(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	p := NewPairing(6, 2*time.Minute, clk)

	code1 := p.Code()
	p.Regenerate()
	code2 := p.Code()
	if code2 == code1 {
		t.Fatalf("expected new code")
	}

	// New code should be consumable.
	if err := p.Consume(code2); err != nil {
		t.Fatalf("consume new: %v", err)
	}
	// Old code should no longer be valid.
	if err := p.Consume(code1); err != ErrPairingCodeInvalid {
		t.Fatalf("expected old invalid, got %v", err)
	}
}

func TestTokenIssueVerifyExpire(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	tok, exp := m.Issue("sess1", "codex-home", 5*time.Minute)
	if tok == "" {
		t.Fatalf("empty token")
	}
	if exp.IsZero() {
		t.Fatalf("zero expiry")
	}

	c, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.SessionID != "sess1" {
		t.Fatalf("SessionID=%q", c.SessionID)
	}
	if c.ClientID != "codex-home" {
		t.Fatalf("ClientID=%q", c.ClientID)
	}

	clk.Advance(5*time.Minute + time.Second)
	if _, err := m.Verify(tok); err != ErrSessionExpired {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestTokenSlidingExpiry(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	tok, exp := m.Issue("sess1", "codex-home", 5*time.Minute)
	if exp.IsZero() {
		t.Fatalf("zero expiry")
	}

	// Before the deadline: valid, and verify slides the deadline out.
	clk.Advance(4 * time.Minute)
	c, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := clk.Now().Add(5 * time.Minute)
	if !c.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt=%v, want %v", c.ExpiresAt, want)
	}

	// Past the original deadline, but inside the slid one.
	clk.Advance(2 * time.Minute)
	if _, err := m.Verify(tok); err != nil {
		t.Fatalf("verify after slide: %v", err)
	}

	// Idle past the slid deadline: expired.
	clk.Advance(5*time.Minute + time.Second)
	if _, err := m.Verify(tok); err != ErrSessionExpired {
		t.Fatalf("expected expired, got %v", err)
	}
	// Expired tokens are collected.
	if _, err := m.Verify(tok); err != ErrUnauthorized {
		t.Fatalf("expected unauthorized after cleanup, got %v", err)
	}
}

func TestTokenNoExpiry(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	tok, exp := m.Issue("sess1", "codex-home", 0)
	if !exp.IsZero() {
		t.Fatalf("exp=%v, want zero", exp)
	}
	clk.Advance(365 * 24 * time.Hour)
	c, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !c.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt=%v, want zero", c.ExpiresAt)
	}
}

func TestTokenExtend(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	if _, err := m.Extend("missing", time.Hour); err != ErrUnauthorized {
		t.Fatalf("expected unauthorized, got %v", err)
	}

	tok, _ := m.Issue("sess1", "codex-home", time.Minute)
	clk.Advance(30 * time.Second)
	exp, err := m.Extend(tok, 10*time.Minute)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if want := clk.Now().Add(10 * time.Minute); !exp.Equal(want) {
		t.Fatalf("exp=%v, want %v", exp, want)
	}
	clk.Advance(9 * time.Minute)
	if _, err := m.Verify(tok); err != nil {
		t.Fatalf("verify after extend: %v", err)
	}

	// ttl <= 0 clears the expiry: the token never expires again.
	exp, err = m.Extend(tok, 0)
	if err != nil {
		t.Fatalf("extend zero: %v", err)
	}
	if !exp.IsZero() {
		t.Fatalf("exp=%v, want zero", exp)
	}
	clk.Advance(24 * time.Hour)
	if _, err := m.Verify(tok); err != nil {
		t.Fatalf("verify after clearing expiry: %v", err)
	}
}

func TestTokenRevoke(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	tok, _ := m.Issue("sess1", "codex-home", time.Hour)
	if !m.Revoke(tok) {
		t.Fatalf("revoke=false, want true")
	}
	if _, err := m.Verify(tok); err != ErrUnauthorized {
		t.Fatalf("expected unauthorized, got %v", err)
	}
	if m.Revoke(tok) {
		t.Fatalf("revoke=true, want false")
	}
}

func TestTokenRevokeSession(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	tokA, _ := m.Issue("sess1", "client-a", time.Hour)
	tokB, _ := m.Issue("sess1", "client-b", time.Hour)
	tokC, _ := m.Issue("sess2", "client-c", time.Hour)

	if n := m.RevokeSession("sess1"); n != 2 {
		t.Fatalf("revoked=%d, want 2", n)
	}
	for _, tok := range []string{tokA, tokB} {
		if _, err := m.Verify(tok); err != ErrUnauthorized {
			t.Fatalf("expected unauthorized, got %v", err)
		}
	}
	if _, err := m.Verify(tokC); err != nil {
		t.Fatalf("other session token must survive: %v", err)
	}
	if n := m.RevokeSession("sess1"); n != 0 {
		t.Fatalf("revoked=%d, want 0", n)
	}
}

func TestTokenOnChangePersistenceEvents(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	type event struct {
		hash    string
		claims  Claims
		deleted bool
	}
	var got []event
	m.OnChange(func(hash string, claims Claims, deleted bool) {
		got = append(got, event{hash: hash, claims: claims, deleted: deleted})
	})

	tok, _ := m.Issue("sess1", "codex-home", time.Hour)
	if len(got) != 1 || got[0].deleted {
		t.Fatalf("issue event = %+v", got)
	}
	if got[0].hash != HashToken(tok) {
		t.Fatalf("sink must receive the hash, not the raw token")
	}
	if got[0].claims.SessionID != "sess1" || got[0].claims.ClientID != "codex-home" {
		t.Fatalf("issue claims = %+v", got[0].claims)
	}

	if _, err := m.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Verify slides a ttl>0 token: an update event must fire.
	if len(got) != 2 || got[1].deleted {
		t.Fatalf("slide event = %+v", got)
	}

	if !m.Revoke(tok) {
		t.Fatalf("revoke=false, want true")
	}
	if len(got) != 3 || !got[2].deleted {
		t.Fatalf("revoke event = %+v", got)
	}

	// Restore inserts an already-persisted record: no callback.
	restored := "restored-raw-token"
	m.Restore(HashToken(restored), Claims{SessionID: "sess9"})
	if len(got) != 3 {
		t.Fatalf("restore must not fire the callback: %+v", got)
	}
	if _, err := m.Verify(restored); err != nil {
		t.Fatalf("verify restored: %v", err)
	}
}

func TestTokenListSessions(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	m.Issue("sess1", "client-a", time.Hour)
	m.Issue("sess1", "client-b", 0)
	m.Issue("sess2", "client-c", time.Hour)

	sessions := m.ListSessions()
	if len(sessions) != 3 {
		t.Fatalf("sessions=%d, want 3", len(sessions))
	}
	byClient := map[string]Claims{}
	for _, s := range sessions {
		byClient[s.ClientID] = s
	}
	if s := byClient["client-b"]; s.SessionID != "sess1" || !s.ExpiresAt.IsZero() {
		t.Fatalf("client-b claims = %+v", s)
	}
	if s := byClient["client-c"]; s.SessionID != "sess2" || s.ExpiresAt.IsZero() {
		t.Fatalf("client-c claims = %+v", s)
	}
}

func TestTokenExtendSession(t *testing.T) {
	clk := NewFakeClock(time.Unix(1000, 0).UTC())
	m := NewTokenManager(clk)

	if _, err := m.ExtendSession("missing", time.Hour); err != ErrSessionNotFound {
		t.Fatalf("expected session not found, got %v", err)
	}

	tokA, _ := m.Issue("sess1", "client-a", time.Hour)
	tokB, _ := m.Issue("sess1", "client-b", time.Hour)
	tokC, _ := m.Issue("sess2", "client-c", time.Hour)

	clk.Advance(59 * time.Minute)
	exp, err := m.ExtendSession("sess1", 2*time.Hour)
	if err != nil {
		t.Fatalf("extend session: %v", err)
	}
	if want := clk.Now().Add(2 * time.Hour); !exp.Equal(want) {
		t.Fatalf("exp=%v, want %v", exp, want)
	}
	// Both session tokens slid past their original deadline...
	clk.Advance(2 * time.Minute)
	for _, tok := range []string{tokA, tokB} {
		if _, err := m.Verify(tok); err != nil {
			t.Fatalf("verify after session extend: %v", err)
		}
	}
	// ...while the other session's token expired on schedule.
	if _, err := m.Verify(tokC); err != ErrSessionExpired {
		t.Fatalf("expected expired, got %v", err)
	}

	// ttl <= 0 clears the expiry for the whole session.
	if _, err := m.ExtendSession("sess1", 0); err != nil {
		t.Fatalf("extend session zero: %v", err)
	}
	clk.Advance(24 * time.Hour)
	if _, err := m.Verify(tokA); err != nil {
		t.Fatalf("verify after clearing: %v", err)
	}
}
