package config

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr            string
	Port                  int
	DefaultTimeoutSec     int
	MaxOutputBytes        int
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
		DefaultTimeoutSec:       120,
		MaxOutputBytes:          1 * 1024 * 1024,
		MaxConcurrency:          3,
		PairingCodeTTLSeconds:   180,
		LockFirstClientAddr:     false,
		AllowAlwaysForDangerous: false,
		KillGraceSec:            5,
	}
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
		case "max_concurrency":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("line %d: max_concurrency: %w", lineNo, err)
			}
			cfg.MaxConcurrency = n
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
