package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestDecisionLookupResultAuthentication(t *testing.T) {
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	devicePub, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	req, err := NewRequest("server", "request", "client", "session", []byte(`{"type":"cmd.run"}`))
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewDecisionLookup("server", "device", req, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignDecisionLookup(q, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecisionLookup(signed, "server", "device", req, devicePub, now); err != nil {
		t.Fatal(err)
	}
	signedRequest := signedRequestFixture(t, req, serverKey)
	pending, err := SignDecisionLookupResult(q, &signedRequest, "PENDING_APPROVAL", "", "", serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecisionLookupResult(q, pending, serverPub, now); err != nil {
		t.Fatal(err)
	}
	decided, err := SignDecisionLookupResult(q, &signedRequest, "AUTHORIZED", "ALLOW_ONCE", "device", serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecisionLookupResult(q, decided, serverPub, now); err != nil {
		t.Fatal(err)
	}
	if decided.Result.DecisionAction != "ALLOW_ONCE" || decided.Result.DecisionDeviceID != "device" {
		t.Fatalf("decided=%+v", decided.Result)
	}
	absent, err := SignDecisionLookupResult(q, nil, "", "", "", serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecisionLookupResult(q, absent, serverPub, now); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewDecisionLookup("server", "device", req, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecisionLookupResult(fresh, decided, serverPub, now); err == nil {
		t.Fatal("response accepted for another challenge")
	}
	if err := VerifyDecisionLookupResult(q, decided, serverPub, now.Add(time.Minute)); err == nil {
		t.Fatal("expired response accepted")
	}
	if _, err := SignDecisionLookupResult(q, nil, "AUTHORIZED", "", "", serverKey); err == nil {
		t.Fatal("absent response with status accepted")
	}
	if _, err := SignDecisionLookupResult(q, &signedRequest, "AUTHORIZED", "ALLOW_ONCE", "", serverKey); err == nil {
		t.Fatal("decision summary without device accepted")
	}
}

func signedRequestFixture(t *testing.T, req Request, serverKey ed25519.PrivateKey) SignedRequest {
	t.Helper()
	signed, err := SignRequest(req, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
