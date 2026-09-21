package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"strings"
	"sync"
	"time"
)

type Pairing struct {
	mu        sync.Mutex
	code      string
	expiresAt time.Time
	used      bool
	// failed counts wrong-code attempts against the current code. After
	// maxPairingAttempts the code is dead even if not expired: minting a
	// fresh one is cheap for the operator, while an unrestricted guessing
	// window would make the 30-bit code brute-forceable within its TTL.
	failed  int
	clock   Clock
	ttl     time.Duration
	codeLen int
}

// maxPairingAttempts bounds wrong-code guesses per issued code. Five
// attempts against 2^30 possibilities leave a success probability below
// 5e-9 even for an attacker who can retry immediately.
const maxPairingAttempts = 5

func NewPairing(codeLen int, ttl time.Duration, clk Clock) *Pairing {
	if clk == nil {
		clk = RealClock{}
	}
	if codeLen <= 0 {
		codeLen = 6
	}
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}

	now := clk.Now()
	code := generateCode(codeLen)
	return &Pairing{code: code, expiresAt: now.Add(ttl), clock: clk, ttl: ttl, codeLen: codeLen}
}

func (p *Pairing) Code() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.code
}

func (p *Pairing) Consume(code string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.used {
		return ErrPairingCodeUsed
	}
	if p.clock.Now().After(p.expiresAt) {
		return ErrPairingCodeExpired
	}
	attempt := subtleUpper(code)
	// Length is public (fixed codeLen); compare the bytes in constant
	// time so a network attacker gains nothing from response timing.
	match := len(attempt) == len(p.code) &&
		subtle.ConstantTimeCompare([]byte(attempt), []byte(p.code)) == 1
	if !match {
		p.failed++
		if p.failed >= maxPairingAttempts {
			// Burn the code: guessing further must be pointless.
			p.used = true
			return ErrPairingCodeLocked
		}
		return ErrPairingCodeInvalid
	}
	p.used = true
	return nil
}

func (p *Pairing) ExpiresAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.expiresAt
}

func (p *Pairing) ExpiresIn() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := time.Until(p.expiresAt)
	if p.clock != nil {
		d = p.expiresAt.Sub(p.clock.Now())
	}
	if d < 0 {
		return 0
	}
	return d
}

func (p *Pairing) Regenerate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock.Now()
	p.code = generateCode(p.codeLen)
	p.expiresAt = now.Add(p.ttl)
	p.used = false
	p.failed = 0
}

func subtleUpper(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

func generateCode(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// A failed CSPRNG read must never degrade into a predictable
		// code: pairing codes gate session issuance.
		panic("racg: crypto/rand failed to seed pairing code: " + err.Error())
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	enc = strings.ToUpper(enc)
	if len(enc) < n {
		return enc
	}
	return enc[:n]
}
