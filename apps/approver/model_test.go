package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"strings"
	"testing"

	"github.com/itolstov/racg/internal/approval"
)

func TestPreviewRequiresPinnedServerSignature(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := approval.NewRequest("server", "request", "agent", "", []byte(`{"type":"cmd.run","payload":{"argv":["echo","hello"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignRequest(r, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	profile := ServerProfile{ServerID: "server", PublicKey: pub}
	text, err := verifiedPreview(profile, data)
	if err != nil || !strings.Contains(text, "hello") {
		t.Fatalf("preview=%s err=%v", text, err)
	}
	for _, bad := range []ServerProfile{{ServerID: "other", PublicKey: pub}, {ServerID: "server"}, {}} {
		if text, err := verifiedPreview(bad, data); err == nil || text != "" {
			t.Fatal("untrusted preview exposed")
		}
	}
	signed.Request.Operation = []byte(`{"argv":["changed"]}`)
	data, err = json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if text, err := verifiedPreview(profile, data); err == nil || text != "" {
		t.Fatal("tampered preview exposed")
	}
}
func TestPreviewEscapesInvisibleCharacters(t *testing.T) {
	got := visibleText("one\n\tvalue\u202etext\x1b\u200b")
	if got != "one\n\tvalue\\u202etext\\x1b\\u200b" {
		t.Fatalf("escaped=%q", got)
	}
}
func TestPreviewHelpIsExplicitAboutAuthority(t *testing.T) {
	var out bytes.Buffer
	_, err := parseOptions([]string{"--help"}, &out)
	if err != flag.ErrHelp {
		t.Fatal(err)
	}
	for _, want := range []string{
		"no network or service connection", "cannot send decisions or execute",
		"passphrase-encrypted", "Allow once or Deny", "never trust a broker-provided key",
		"current pending", "--key", "--server-profile", "--request",
		"Auto-lock field", "Decision validity", "nothing is sent",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help missing %q", want)
		}
	}
}
