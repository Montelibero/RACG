package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

func TestOfflineDecisionEnvelopeVerifies(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := &DeviceKey{ID: "device-test", Private: private, Public: public}
	request, err := approval.NewRequest("server", "request", "agent", "", []byte(`{"type":"cmd.run","payload":{"argv":["echo","hello"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	validUntil := time.Now().Add(time.Minute)
	data, err := decisionEnvelope(request, key.ID, "ALLOW_ONCE", validUntil, key)
	if err != nil {
		t.Fatal(err)
	}
	var signed approval.SignedDecision
	if err := json.Unmarshal([]byte(data), &signed); err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDecision(request, signed, key.ID, public, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := decisionEnvelope(request, "other", "ALLOW_ONCE", validUntil, key); err == nil {
		t.Fatal("device mismatch accepted")
	}
	key.lock()
	if _, err := decisionEnvelope(request, key.ID, "DENY", validUntil, key); err == nil {
		t.Fatal("locked key accepted")
	}
}
