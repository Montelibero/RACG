// Package service composes the privileged authority and unprivileged broker
// with separate state and explicit OS identities. It intentionally has no CLI
// or deployment wiring yet.
package service

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	DefaultAuthorityStateDir = "/var/lib/racg-authority"
	DefaultBrokerStateDir    = "/var/lib/racg-broker"
	DefaultAuthoritySocket   = "/run/racg/authority.sock"
	DefaultAdminSocket       = "/run/racg/authority-admin.sock"
)

type AuthorityConfig struct {
	ServerID    string
	StateDir    string
	SocketPath  string
	AdminSocket string
	BrokerUID   int
	BrokerGID   int
	AdminUID    int
	AdminGID    int
}

type BrokerConfig struct {
	StateDir     string
	SocketPath   string
	AuthorityUID int
	AuthorityGID int
}

type Config struct {
	Authority AuthorityConfig
	Broker    BrokerConfig
}

func DefaultAuthorityConfig() AuthorityConfig {
	return AuthorityConfig{
		StateDir:    DefaultAuthorityStateDir,
		SocketPath:  DefaultAuthoritySocket,
		AdminSocket: DefaultAdminSocket,
	}
}

func DefaultBrokerConfig() BrokerConfig {
	return BrokerConfig{
		StateDir:   DefaultBrokerStateDir,
		SocketPath: DefaultAuthoritySocket,
	}
}

func (c AuthorityConfig) DatabasePath() string {
	return filepath.Join(c.StateDir, "authority.db")
}

func (c AuthorityConfig) LockPath() string {
	return filepath.Join(c.StateDir, "authority.lock")
}

func (c AuthorityConfig) PrivateKeyPath() string {
	return filepath.Join(c.StateDir, "authority.key")
}

func (c AuthorityConfig) Validate() error {
	if c.ServerID == "" {
		return errors.New("authority server ID required")
	}
	if err := validatePrivateStateDir(c.StateDir); err != nil {
		return fmt.Errorf("authority state directory: %w", err)
	}
	if err := validateSocketPath(c.SocketPath); err != nil {
		return fmt.Errorf("authority socket: %w", err)
	}
	if c.BrokerUID < 0 || c.BrokerGID < 0 {
		return errors.New("authority broker UID and GID required")
	}
	if err := validateSocketPath(c.AdminSocket); err != nil {
		return fmt.Errorf("authority admin socket: %w", err)
	}
	if c.AdminUID < 0 || c.AdminGID < 0 {
		return errors.New("authority admin UID and GID required")
	}
	if c.SocketPath == c.AdminSocket {
		return errors.New("broker and admin sockets must be separate")
	}
	return nil
}

func (c BrokerConfig) Validate() error {
	if err := validatePrivateStateDir(c.StateDir); err != nil {
		return fmt.Errorf("broker state directory: %w", err)
	}
	if err := validateSocketPath(c.SocketPath); err != nil {
		return fmt.Errorf("broker authority socket: %w", err)
	}
	if c.AuthorityUID < 0 || c.AuthorityGID < 0 {
		return errors.New("broker authority UID and GID required")
	}
	return nil
}

func (c Config) Validate() error {
	if err := c.Authority.Validate(); err != nil {
		return err
	}
	if err := c.Broker.Validate(); err != nil {
		return err
	}
	if pathsOverlap(c.Authority.StateDir, c.Broker.StateDir) || pathsOverlap(c.Broker.StateDir, c.Authority.StateDir) {
		return errors.New("authority and broker state directories must be separate")
	}
	if c.Authority.SocketPath != c.Broker.SocketPath {
		return errors.New("authority and broker socket paths do not match")
	}
	if pathsOverlap(c.Authority.SocketPath, c.Authority.StateDir) || pathsOverlap(c.Authority.SocketPath, c.Broker.StateDir) {
		return errors.New("authority socket must not be inside a state directory")
	}
	if pathsOverlap(c.Authority.AdminSocket, c.Authority.StateDir) || pathsOverlap(c.Authority.AdminSocket, c.Broker.StateDir) {
		return errors.New("admin socket must not be inside a state directory")
	}
	return nil
}

func pathsOverlap(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return path == directory
	}
	return relative == "." || (!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && relative != "..")
}

func validateSocketPath(path string) error {
	path, err := canonicalAbsolute(path)
	if err != nil {
		return err
	}
	if path == string(filepath.Separator) {
		return errors.New("path is the root directory")
	}
	return nil
}

func validatePrivateStateDir(path string) error {
	path, err := canonicalAbsolute(path)
	if err != nil {
		return err
	}
	if path == string(filepath.Separator) {
		return errors.New("path is the root directory")
	}
	return nil
}

func canonicalAbsolute(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("absolute canonical path required")
	}
	clean := filepath.Clean(path)
	if clean != path {
		return "", errors.New("absolute canonical path required")
	}
	return clean, nil
}

// ApplyTOML parses the deliberately small service configuration format. Unknown
// keys are ignored for forward-compatible transport, as in the interactive config.
func ApplyTOML(config *Config, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line, err := tomlLine(scanner.Text(), lineNo)
		if err != nil {
			return err
		}
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if err := applyServiceTOML(config, lineNo, key, value); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func tomlLine(raw string, lineNo int) (string, error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	if index := strings.Index(line, "#"); index >= 0 {
		line = strings.TrimSpace(line[:index])
	}
	return line, nil
}

func applyServiceTOML(config *Config, lineNo int, key, value string) error {
	stringTargets := map[string]*string{
		"authority_server_id":     &config.Authority.ServerID,
		"authority_state_dir":     &config.Authority.StateDir,
		"authority_socket":        &config.Authority.SocketPath,
		"authority_admin_socket":  &config.Authority.AdminSocket,
		"broker_state_dir":        &config.Broker.StateDir,
		"broker_authority_socket": &config.Broker.SocketPath,
	}
	if target, exists := stringTargets[key]; exists {
		parsed, err := parseTOMLString(value)
		if err != nil {
			return fmt.Errorf("line %d: %s: %w", lineNo, key, err)
		}
		*target = parsed
		return nil
	}
	intTargets := map[string]*int{
		"authority_broker_uid": &config.Authority.BrokerUID,
		"authority_broker_gid": &config.Authority.BrokerGID,
		"authority_admin_uid":  &config.Authority.AdminUID,
		"authority_admin_gid":  &config.Authority.AdminGID,
		"broker_authority_uid": &config.Broker.AuthorityUID,
		"broker_authority_gid": &config.Broker.AuthorityGID,
	}
	if target, exists := intTargets[key]; exists {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("line %d: %s: expected integer", lineNo, key)
		}
		*target = parsed
		return nil
	}
	return nil
}

func parseTOMLString(value string) (string, error) {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", errors.New("expected quoted string")
	}
	return value[1 : len(value)-1], nil
}

// prepareStateDirectory creates or adopts exactly one leaf directory. It does
// not follow or create a symlinked hierarchy, and rejects writable parents.
func prepareStateDirectory(path string) error {
	path, err := canonicalAbsolute(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("state parent is not a real directory")
	}
	if parentInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("state parent is group- or world-writable (%s mode %v)", parent, parentInfo.Mode())
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state path is not a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return os.Chown(path, os.Geteuid(), os.Getegid())
}

func PrepareAuthorityState(config AuthorityConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	return prepareStateDirectory(config.StateDir)
}

func PrepareBrokerState(config BrokerConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	return prepareStateDirectory(config.StateDir)
}
