package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fastKeyEncryption(t *testing.T) {
	t.Helper()
	old := encryptedKeyWorkFactor
	encryptedKeyWorkFactor = 10
	t.Cleanup(func() { encryptedKeyWorkFactor = old })
}

func TestDeviceKeyFileRoundTrip(t *testing.T) {
	fastKeyEncryption(t)
	path := filepath.Join(t.TempDir(), "signing.key")
	key, err := newDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveDeviceKey(path, key.ID, key.Private, "correct horse"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("key mode=%v", got)
	}
	loaded, err := loadDeviceKey(path, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != key.ID || !ed25519.PublicKey.Equal(loaded.Public, key.Public) {
		t.Fatal("loaded identity changed")
	}
	if _, err := loadDeviceKey(path, "wrong horse"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if err := saveDeviceKey(path, key.ID, key.Private, "another horse"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite error=%v", err)
	}
	key.lock()
	if len(key.Private) != 0 || key.Public != nil {
		t.Fatal("locked key retained material")
	}
}
