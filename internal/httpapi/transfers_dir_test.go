package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itolstov/racg/internal/config"
)

func TestTransferDirFallbackIsPrivateAndStable(t *testing.T) {
	api := New(config.Defaults())
	api.cfg.DBPath = "file::memory:?cache=shared"

	dir := api.transferDir()
	base := filepath.Base(dir)
	if !strings.HasPrefix(base, "racg-transfers-") || base == "racg-transfers" {
		t.Fatalf("fallback dir not randomized: %s", dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("fallback dir mode=%v", info.Mode())
	}
	// Repeated calls must reuse one directory per API instance.
	if again := api.transferDir(); again != dir {
		t.Fatalf("fallback dir changed between calls: %s vs %s", dir, again)
	}

	// Empty DBPath gets the same private treatment.
	empty := New(config.Defaults())
	empty.cfg.DBPath = ""
	if d := empty.transferDir(); filepath.Base(d) == "racg-transfers" || !strings.HasPrefix(filepath.Base(d), "racg-transfers-") {
		t.Fatalf("empty DBPath fallback: %s", d)
	}

	// File-backed databases keep the deterministic sibling directory.
	fileBacked := New(config.Defaults())
	fileBacked.cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
	if want := fileBacked.cfg.DBPath + ".transfers"; fileBacked.transferDir() != want {
		t.Fatalf("file-backed dir=%s want=%s", fileBacked.transferDir(), want)
	}
}
