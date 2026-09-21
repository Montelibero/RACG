package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalizeOpPathResolvesSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed")
	outside := filepath.Join(dir, "outside")
	for _, d := range []string{allowed, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(outside, "secret.conf")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "link.conf")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	e := NewEngine()
	e.AddAlways(Rule{ID: "allowed-dir", OpType: "fs.read", Path: &PathRule{Prefix: allowed + string(os.PathSeparator)}})

	// Without canonicalization the symlinked path sits inside the allowed
	// prefix and would be auto-approved; the resolved copy must not match.
	escaped := Op{Type: "fs.read", Payload: mustJSON(t, map[string]any{"path": link})}
	if _, ok := e.Match("sess1", escaped); !ok {
		t.Fatal("symlink inside allowed dir unexpectedly matched prefix rule before canonicalization sanity check")
	}
	if _, ok := e.Match("sess1", CanonicalizeOpPath(escaped)); ok {
		t.Fatal("canonicalized symlink escape must not match the allowed-dir rule")
	}

	// A missing file is a canonicalization no-op: the payload stays
	// verbatim (admission owns the contract; execution fails on its own).
	missing := Op{Type: "fs.read", Payload: mustJSON(t, map[string]any{"path": filepath.Join(allowed, "missing.conf")})}
	if got := CanonicalizeOpPath(missing); string(got.Payload) != string(missing.Payload) {
		t.Fatalf("missing file payload rewritten: %s", got.Payload)
	}
	plain := filepath.Join(allowed, "plain.conf")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := Op{Type: "fs.read", Payload: mustJSON(t, map[string]any{"path": plain})}
	if _, ok := e.Match("sess1", CanonicalizeOpPath(real)); !ok {
		t.Fatal("existing file in allowed dir must still match after canonicalization")
	}
}

func TestCanonicalizeOpPathUploadResolvesParent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "incoming")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "link")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}

	// The uploaded file does not exist yet; the parent symlink must still
	// resolve, so a rule scoped to the real directory rejects the link path.
	op := Op{Type: "fs.upload", Payload: mustJSON(t, map[string]any{"path": filepath.Join(linked, "payload.bin"), "upload_id": "0123456789abcdef0123456789abcdef"})}
	got := CanonicalizeOpPath(op)
	var payload struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(got.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(target, "payload.bin"); payload.Path != want {
		t.Fatalf("upload path=%q want %q", payload.Path, want)
	}

	// Non-path and non-absolute operations pass through untouched.
	argv := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{"argv": []string{"ls"}})}
	if got := CanonicalizeOpPath(argv); string(got.Payload) != string(argv.Payload) {
		t.Fatalf("cmd.run payload rewritten: %s", got.Payload)
	}
}
