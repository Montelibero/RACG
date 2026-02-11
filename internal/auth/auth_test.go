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
