package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"github.com/itolstov/racg/internal/approval"
)

func TestUICreatesOfflineDecision(t *testing.T) {
	fastKeyEncryption(t)
	directory := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := approval.NewRequest("server", "request-1", "agent-1", "", []byte(`{"type":"cmd.run","payload":{"argv":["echo","hello"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignRequest(request, private)
	if err != nil {
		t.Fatal(err)
	}
	profileData, err := json.Marshal(ServerProfile{ServerID: "server", PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	requestData, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(directory, "profile.json")
	requestPath := filepath.Join(directory, "request.json")
	keyPath := filepath.Join(directory, "device.key")
	if err := os.WriteFile(profilePath, profileData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestPath, requestData, 0o600); err != nil {
		t.Fatal(err)
	}
	u := newPreviewUI(options{}, test.NewApp())
	u.canvas()
	u.profilePath.SetText(profilePath)
	u.requestPath.SetText(requestPath)
	u.keyPath.SetText(keyPath)
	u.passphrase.SetText("correct horse")
	u.confirmPassphrase.SetText("correct horse")
	test.Tap(u.createKey)
	if u.key == nil || len(u.key.Public) != ed25519.PublicKeySize {
		t.Fatalf("key was not created: %s", u.status.Text)
	}
	test.Tap(u.verify)
	if u.request.RequestID != "request-1" || !strings.Contains(u.preview.Text, "hello") {
		t.Fatalf("request was not verified: %s", u.status.Text)
	}
	test.Tap(u.allow)
	if u.decision.Text != "" {
		t.Fatal("decision created without validity")
	}
	u.decisionValidity.SetText("5m")
	test.Tap(u.allow)
	if u.decision.Text == "" {
		t.Fatalf("decision was not created: %s", u.status.Text)
	}
	var envelope approval.SignedDecision
	if err := json.Unmarshal([]byte(u.decision.Text), &envelope); err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDecision(u.request, envelope, u.key.ID, u.key.Public, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	test.Tap(u.lockNow)
	if u.key != nil || !u.allow.Disabled() || !u.deny.Disabled() {
		t.Fatal("lock did not disable signing")
	}
}

func TestUIVerificationFailureClearsPreview(t *testing.T) {
	u := newPreviewUI(options{profile: "/nonexistent-racg-test-profile"}, test.NewApp())
	u.canvas()
	u.preview.SetText("previous verified request")
	test.Tap(u.verify)
	if u.preview.Text != "" {
		t.Fatal("stale request remained visible after verification failed")
	}
	if !strings.HasPrefix(u.status.Text, "Verification failed:") {
		t.Fatal("verification error not shown")
	}
}
