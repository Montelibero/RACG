package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignedRequestAndDecision(t *testing.T) {
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	devicePub, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	req, err := NewRequest("server-1", "request-1", "client-1", "session-1", []byte(`{"type":"cmd.run","payload":{"argv":["echo","ok"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignRequest(req, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(signed, "server-1", serverPub); err != nil {
		t.Fatal(err)
	}
	decision, err := SignDecision(req, "device-1", "ALLOW_ONCE", nil, now.Add(time.Minute), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecision(req, decision, "device-1", devicePub, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(signed, "other-server", serverPub); err == nil {
		t.Fatal("wrong server accepted")
	}
	if err := VerifyDecision(req, decision, "other-device", devicePub, now); err == nil {
		t.Fatal("wrong device accepted")
	}
	if err := VerifyDecision(req, decision, "device-1", devicePub, now.Add(time.Minute)); err == nil {
		t.Fatal("expired decision accepted")
	}
	if err := VerifyDecision(req, decision, "device-1", serverPub, now); err == nil {
		t.Fatal("server key accepted as device")
	}
}

func TestEveryRequestFieldIsBound(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	for _, field := range []string{"server", "request", "client", "session", "operation", "challenge", "version"} {
		t.Run(field, func(t *testing.T) {
			req, err := NewRequest("s", "r", "c", "session", []byte(`{"type":"fs.read","payload":{"path":"/tmp/a"}}`))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := SignRequest(req, key)
			if err != nil {
				t.Fatal(err)
			}
			dec, err := SignDecision(req, "device", "DENY", nil, now.Add(time.Minute), key)
			if err != nil {
				t.Fatal(err)
			}
			changed := req
			switch field {
			case "server":
				changed.ServerID = "other"
			case "request":
				changed.RequestID = "other"
			case "client":
				changed.ClientID = "other"
			case "session":
				changed.SessionID = "other"
			case "operation":
				changed.Operation = []byte(`{"type":"fs.read","payload":{"path":"/etc/shadow"}}`)
			case "challenge":
				changed.Challenge = append([]byte(nil), req.Challenge...)
				changed.Challenge[0] ^= 1
			case "version":
				changed.Version++
			}
			signed.Request = changed
			if VerifyRequest(signed, "s", pub) == nil {
				t.Fatal("modified request accepted")
			}
			if VerifyDecision(changed, dec, "device", pub, now) == nil {
				t.Fatal("decision accepted for modified request")
			}
		})
	}
}

func TestGrantAndDecisionCannotBeWidened(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	req, _ := NewRequest("s", "r", "c", "session", []byte(`{"type":"cmd.run"}`))
	grant := &Grant{Scope: []byte(`{"op_type":"cmd.run","cmd":{"argv_prefix":["echo"]}}`), ExpiresAt: now.Add(4 * time.Hour).Format(time.RFC3339Nano)}
	decision, err := SignDecision(req, "d", "ALLOW_UNTIL", grant, now.Add(time.Minute), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecision(req, decision, "d", pub, now); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"action", "scope", "expiry", "validity"} {
		changed := decision
		g := *decision.Decision.Grant
		changed.Decision.Grant = &g
		switch field {
		case "action":
			changed.Decision.Action = "ALLOW_ALWAYS"
		case "scope":
			g.Scope = []byte(`{"op_type":"cmd.run","cmd":{"argv_prefix":["sh"]}}`)
		case "expiry":
			g.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339Nano)
		case "validity":
			changed.Decision.ValidUntil = now.Add(24 * time.Hour).Format(time.RFC3339Nano)
		}
		if VerifyDecision(req, changed, "d", pub, now) == nil {
			t.Fatalf("modified %s accepted", field)
		}
	}
	// A grant's expiry is independent from how long the signed decision can be delivered.
	if _, err := SignDecision(req, "d", "ALLOW_UNTIL", &Grant{Scope: grant.Scope}, now.Add(time.Minute), key); err == nil {
		t.Fatal("timed grant without expiry accepted")
	}
	if _, err := SignDecision(req, "d", "ALLOW_ONCE", grant, now.Add(time.Minute), key); err == nil {
		t.Fatal("one-shot approval silently created a grant")
	}
}

func TestRequestsHaveFreshChallengesAndOwnOperationBytes(t *testing.T) {
	op := []byte(`{"type":"cmd.run"}`)
	a, err := NewRequest("s", "r", "c", "", op)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRequest("s", "r", "c", "", op)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Challenge) == string(b.Challenge) {
		t.Fatal("challenge reused")
	}
	op[0] = 'x'
	if a.Operation[0] != '{' {
		t.Fatal("request aliases caller-owned operation")
	}
}
