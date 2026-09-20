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
	if cfg.MaxTransferBytes != 0 {
		t.Fatalf("MaxTransferBytes=%d, want unlimited", cfg.MaxTransferBytes)
	}
	if cfg.PairingCodeTTLSeconds == 0 {
		t.Fatalf("PairingCodeTTLSeconds=%d", cfg.PairingCodeTTLSeconds)
	}
	if cfg.SessionTTLHours != 8 {
		t.Fatalf("SessionTTLHours=%d, want 8", cfg.SessionTTLHours)
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
max_transfer_bytes = 123456
lock_first_client_addr = true
session_ttl_hours = 0
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
	if cfg.MaxTransferBytes != 0 {
		t.Fatalf("MaxTransferBytes=%d, deprecated config key must not cap transfers", cfg.MaxTransferBytes)
	}
	if !cfg.LockFirstClientAddr {
		t.Fatalf("LockFirstClientAddr=false")
	}
	if cfg.SessionTTLHours != 0 {
		t.Fatalf("SessionTTLHours=%d, want 0 (explicit no-expiry)", cfg.SessionTTLHours)
	}
}
