package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr            string
	Port                  int
	DBPath                string
	DefaultTimeoutSec     int
	MaxOutputBytes        int
	MaxTransferBytes      int64
	MaxConcurrency        int
	PairingCodeTTLSeconds int

	LockFirstClientAddr     bool
	AllowAlwaysForDangerous bool
	KillGraceSec            int
}

func Defaults() Config {
	return Config{
		ListenAddr:              "127.0.0.1",
		Port:                    8777,
		DBPath:                  defaultDBPath(),
		DefaultTimeoutSec:       120,
		MaxOutputBytes:          1 * 1024 * 1024,
		MaxTransferBytes:        100 * 1024 * 1024,
		MaxConcurrency:          3,
		PairingCodeTTLSeconds:   180,
		LockFirstClientAddr:     false,
		AllowAlwaysForDangerous: false,
		KillGraceSec:            5,
	}
}

func defaultDBPath() string {
	return filepath.Join(stateDir(), "racg.db")
}

func ProfileDBPath(profile string) string {
	name := safeProfileName(profile)
	if name == "" {
		name = "default"
	}
	return filepath.Join(stateDir(), "profiles", name+".db")
}

func stateDir() string {
	if runtime.GOOS != "windows" {
		if dir := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); dir != "" {
			return filepath.Join(dir, "racg")
		}
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return filepath.Join(home, ".local", "state", "racg")
		}
	}
	if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "racg")
	}
	return "."
}

func safeProfileName(profile string) string {
	profile = strings.TrimSpace(profile)
	var b strings.Builder
	lastDash := false
	for _, r := range profile {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// ApplyTOMLSimple applies a minimal top-level TOML subset: `key = value`.
// Supported value types: quoted strings, ints, bool.
// This intentionally ignores TOML sections/arrays to keep MVP dependency-free.
func ApplyTOMLSimple(cfg *Config, r io.Reader) error {
	s := bufio.NewScanner(r)
	for lineNo := 1; s.Scan(); lineNo++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip trailing comment.
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}

		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)

		switch key {
		case "listen_addr":
			str, err := parseTOMLString(val)
			if err != nil {
				return fmt.Errorf("line %d: listen_addr: %w", lineNo, err)
			}
			cfg.ListenAddr = str
		case "port":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("line %d: port: %w", lineNo, err)
			}
			cfg.Port = n
		case "db_path":
			str, err := parseTOMLString(val)
			if err != nil {
				return fmt.Errorf("line %d: db_path: %w", lineNo, err)
			}
			cfg.DBPath = str
		case "max_concurrency":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("line %d: max_concurrency: %w", lineNo, err)
			}
			cfg.MaxConcurrency = n
		case "max_transfer_bytes":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil || n <= 0 {
				return fmt.Errorf("line %d: max_transfer_bytes: expected positive integer", lineNo)
			}
			cfg.MaxTransferBytes = n
		case "lock_first_client_addr":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return fmt.Errorf("line %d: lock_first_client_addr: %w", lineNo, err)
			}
			cfg.LockFirstClientAddr = b
		case "allow_always_for_dangerous":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return fmt.Errorf("line %d: allow_always_for_dangerous: %w", lineNo, err)
			}
			cfg.AllowAlwaysForDangerous = b
		case "kill_grace_sec":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("line %d: kill_grace_sec: %w", lineNo, err)
			}
			cfg.KillGraceSec = n
		default:
			// Ignore unknown keys in MVP.
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	return nil
}

func parseTOMLString(v string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", fmt.Errorf("expected quoted string")
	}
	// MVP: no escape handling.
	return v[1 : len(v)-1], nil
}
