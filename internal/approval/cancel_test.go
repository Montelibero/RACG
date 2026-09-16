package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestCancellationBindingAndResultAuthentication(t *testing.T) {
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	agentPub, agentKey, _ := ed25519.GenerateKey(rand.Reader)
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	now := time.Now()
	cancellation, err := NewCancellation("server", "agent", "request", nonce, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignCancellation(cancellation, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCancellation(signed, "server", "agent", "request", agentPub, now); err != nil {
		t.Fatal(err)
	}
	result, err := SignCancellationResult(cancellation, "CANCELED", true, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCancellationResult(cancellation, result, serverPub, now); err != nil {
		t.Fatal(err)
	}
	if !result.Result.Canceled || result.Result.Status != "CANCELED" {
		t.Fatalf("result=%+v", result.Result)
	}
	tampered := signed
	tampered.Cancellation.RequestID = "other"
	if err := VerifyCancellation(tampered, "server", "agent", "other", agentPub, now); err == nil {
		t.Fatal("tampered cancellation accepted")
	}
	if err := VerifyCancellationResult(cancellation, result, serverPub, now.Add(time.Minute)); err == nil {
		t.Fatal("expired response accepted")
	}
}
