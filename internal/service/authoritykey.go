package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const authorityKeyPEMType = "PRIVATE KEY"

// LoadOrCreateAuthoritySigningKey persists the authority's long-lived identity
// as standard PKCS#8/PEM. The service must start unattended, so the file is
// protected by directory ownership and mode 0600 rather than a passphrase.
func LoadOrCreateAuthoritySigningKey(path string) (ed25519.PrivateKey, error) {
	path, err := canonicalAbsolute(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := writeAuthoritySigningKey(path, private); err != nil {
			return nil, err
		}
		return private, nil
	} else if err != nil {
		return nil, err
	}
	return LoadAuthoritySigningKey(path)
}

func LoadAuthoritySigningKey(path string) (ed25519.PrivateKey, error) {
	path, err := canonicalAbsolute(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("authority signing key is not a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("authority signing key mode %v must be 0600", info.Mode().Perm())
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != authorityKeyPEMType || len(block.Bytes) == 0 {
		return nil, errors.New("invalid authority signing key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse authority signing key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("authority signing key is not Ed25519")
	}
	return append(ed25519.PrivateKey(nil), private...), nil
}

func writeAuthoritySigningKey(path string, private ed25519.PrivateKey) error {
	if len(private) != ed25519.PrivateKeySize {
		return errors.New("valid Ed25519 authority signing key required")
	}
	parsed, err := x509.MarshalPKCS8PrivateKey(append(ed25519.PrivateKey(nil), private...))
	if err != nil {
		return err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: authorityKeyPEMType, Bytes: parsed})
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
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
