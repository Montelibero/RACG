package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerProfileRoundTrip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "profiles", "server.json")
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := ServerProfile{ServerID: "server", PublicKey: public}
	if err := SaveServerProfile(path, profile); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("profile mode=%v", got)
	}
	loaded, err := LoadServerProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ServerID != profile.ServerID || string(loaded.PublicKey) != string(profile.PublicKey) {
		t.Fatalf("loaded=%+v", loaded)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerProfile(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("unsafe profile error=%v", err)
	}
}
