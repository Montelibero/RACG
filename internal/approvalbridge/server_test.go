package approvalbridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/httpapi"
)

type fakeBackend struct{ decision PhoneDecision }

func (f *fakeBackend) PendingForPhone() []httpapi.PhoneRequest { return nil }

func (f *fakeBackend) RequestForPhone(string) (httpapi.PhoneRequest, bool) {
	return httpapi.PhoneRequest{ID: "request", OpSHA256: "abc"}, true
}

func (f *fakeBackend) DecideForPhone(requestID, decision, deviceID string) error {
	f.decision = PhoneDecision{RequestID: requestID, Decision: decision, DeviceID: deviceID}
	return nil
}

func TestBridgeChallengesAndAcceptsSignedDecision(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RACG_PHONE_PAIRING_CODE", "test-code")
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	backend := &fakeBackend{}
	socket := filepath.Join(dir, "bridge.sock")
	server := NewServer(backend, NewDeviceRegistry(filepath.Join(dir, "devices.json")))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, socket, server) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bridge socket was not created")
		}
		time.Sleep(5 * time.Millisecond)
	}

	client := NewClient(socket)
	if err := client.Pair("test-code", "phone", public); err != nil {
		t.Fatalf("pair: %v", err)
	}
	challenge, err := client.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	decision := PhoneDecision{DeviceID: "phone", RequestID: "request", Decision: "ALLOW_ONCE", OpSHA256: "abc", Challenge: challenge}
	message := DecisionMessage(decision.DeviceID, decision.RequestID, decision.Decision, decision.OpSHA256, decision.Challenge)
	hash := sha256.Sum256(message)
	decision.Signature, err = ecdsa.SignASN1(rand.Reader, private, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Decide(decision); err != nil {
		t.Fatalf("decision: %v", err)
	}
	if backend.decision.RequestID != "request" || backend.decision.DeviceID != "phone" {
		t.Fatalf("backend decision=%+v", backend.decision)
	}
}
