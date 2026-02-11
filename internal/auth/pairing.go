package auth

import (
	"crypto/rand"
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
	clock     Clock
	ttl       time.Duration
	codeLen   int
}

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

	if subtleUpper(code) != p.code {
		return ErrPairingCodeInvalid
	}
	if p.used {
		return ErrPairingCodeUsed
	}
	if p.clock.Now().After(p.expiresAt) {
		return ErrPairingCodeExpired
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
}

func subtleUpper(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

func generateCode(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("A", n)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	enc = strings.ToUpper(enc)
	if len(enc) < n {
		return enc
	}
	return enc[:n]
}
