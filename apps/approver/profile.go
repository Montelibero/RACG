package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const profileFileVersion = 1

type storedProfile struct {
	Version int           `json:"version"`
	Profile ServerProfile `json:"profile"`
}

// SaveServerProfile atomically stores a profile created by trusted SSH
// enrollment. It refuses a group/world-writable parent and never follows a
// symlinked profile path.
func SaveServerProfile(path string, profile ServerProfile) error {
	if err := validateProfile(profile); err != nil {
		return err
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("profile parent is not a real directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("profile parent is group- or world-writable")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("profile path is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.Marshal(storedProfile{Version: profileFileVersion, Profile: profile})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			temporary.Close()
			os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func LoadServerProfile(path string) (ServerProfile, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ServerProfile{}, err
	}
	if !info.Mode().IsRegular() {
		return ServerProfile{}, errors.New("profile path is not a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return ServerProfile{}, fmt.Errorf("profile mode %v must be 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ServerProfile{}, err
	}
	var stored storedProfile
	if err := json.Unmarshal(data, &stored); err != nil {
		return ServerProfile{}, fmt.Errorf("decode profile: %w", err)
	}
	if stored.Version != profileFileVersion {
		return ServerProfile{}, fmt.Errorf("unsupported profile version %d", stored.Version)
	}
	if err := validateProfile(stored.Profile); err != nil {
		return ServerProfile{}, err
	}
	return stored.Profile, nil
}

func validateProfile(profile ServerProfile) error {
	if profile.ServerID == "" {
		return errors.New("profile server ID required")
	}
	if len(profile.PublicKey) != ed25519.PublicKeySize {
		return errors.New("profile requires an Ed25519 public key")
	}
	return nil
}
