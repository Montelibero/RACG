package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.ListenAddr != "127.0.0.1" {
		t.Fatalf("ListenAddr=%q", cfg.ListenAddr)
	}
	if cfg.Port != 8777 {
		t.Fatalf("Port=%d", cfg.Port)
	}
	if cfg.DBPath == "" {
		t.Fatalf("DBPath empty")
	}
	if filepath.Base(cfg.DBPath) != "racg.db" {
		t.Fatalf("DBPath=%q, want racg.db basename", cfg.DBPath)
	}
	if filepath.Dir(cfg.DBPath) == "." {
		t.Fatalf("DBPath=%q, want user-state path by default", cfg.DBPath)
	}
	if cfg.MaxConcurrency != 3 {
		t.Fatalf("MaxConcurrency=%d", cfg.MaxConcurrency)
	}
	if cfg.DefaultTimeoutSec != 120 {
		t.Fatalf("DefaultTimeoutSec=%d", cfg.DefaultTimeoutSec)
	}
	if cfg.MaxOutputBytes < 1024*1024 {
		t.Fatalf("MaxOutputBytes=%d", cfg.MaxOutputBytes)
	}
	if cfg.PairingCodeTTLSeconds == 0 {
		t.Fatalf("PairingCodeTTLSeconds=%d", cfg.PairingCodeTTLSeconds)
	}
}

func TestProfileDBPath(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "state"))

	got := ProfileDBPath("docker/prod")
	want := filepath.Join(os.Getenv("XDG_STATE_HOME"), "racg", "profiles", "docker-prod.db")
	if got != want {
		t.Fatalf("ProfileDBPath=%q want %q", got, want)
	}
}

func TestParseConfigTOMLSimple(t *testing.T) {
	in := strings.NewReader(`
# comment
listen_addr = "0.0.0.0"
port = 55555
db_path = "racg-test.db"
max_concurrency = 7
lock_first_client_addr = true
`)

	cfg := Defaults()
	if err := ApplyTOMLSimple(&cfg, in); err != nil {
		t.Fatalf("ApplyTOMLSimple: %v", err)
	}

	if cfg.ListenAddr != "0.0.0.0" {
		t.Fatalf("ListenAddr=%q", cfg.ListenAddr)
	}
	if cfg.Port != 55555 {
		t.Fatalf("Port=%d", cfg.Port)
	}
	if cfg.DBPath != "racg-test.db" {
		t.Fatalf("DBPath=%q", cfg.DBPath)
	}
	if cfg.MaxConcurrency != 7 {
		t.Fatalf("MaxConcurrency=%d", cfg.MaxConcurrency)
	}
	if !cfg.LockFirstClientAddr {
		t.Fatalf("LockFirstClientAddr=false")
	}
}
