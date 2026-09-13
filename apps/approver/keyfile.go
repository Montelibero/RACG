package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
)

const (
	encryptedKeyVersion = 1
	encryptedKeyLimit   = 4096
)

// age's passphrase format uses scrypt. The default is intended for interactive
// use; tests lower both sides only to keep the suite fast.
var encryptedKeyWorkFactor = 18

type DeviceKey struct {
	ID      string
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	mu      sync.RWMutex
}

type encryptedKeyPayload struct {
	Version  int    `json:"version"`
	DeviceID string `json:"device_id"`
	Seed     []byte `json:"seed"`
}

func newDeviceKey() (*DeviceKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	private := ed25519.NewKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	return &DeviceKey{ID: "device-" + hex.EncodeToString(idBytes), Private: private, Public: private.Public().(ed25519.PublicKey)}, nil
}

// saveDeviceKey encrypts with age's passphrase format and refuses to overwrite.
// The temporary file is fsynced before an atomic same-directory rename.
func saveDeviceKey(path, deviceID string, private ed25519.PrivateKey, passphrase string) error {
	if deviceID == "" || len(private) != ed25519.PrivateKeySize {
		return errors.New("valid device identity and signing key required")
	}
	if path == "" {
		return errors.New("key path required")
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	recipient.SetWorkFactor(encryptedKeyWorkFactor)
	payload, err := json.Marshal(encryptedKeyPayload{
		Version:  encryptedKeyVersion,
		DeviceID: deviceID,
		Seed:     private.Seed(),
	})
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("signing key already exists: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			temporary.Close()
			os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	encrypted, err := age.Encrypt(temporary, recipient)
	if err != nil {
		return err
	}
	if _, err := io.Copy(encrypted, bytes.NewReader(payload)); err != nil {
		encrypted.Close()
		return err
	}
	if err := encrypted.Close(); err != nil {
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
	removeTemp = false
	return nil
}

func loadDeviceKey(path, passphrase string) (*DeviceKey, error) {
	if path == "" {
		return nil, errors.New("key path required")
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	identity.SetMaxWorkFactor(encryptedKeyWorkFactor)
	encrypted, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer encrypted.Close()
	decrypted, err := age.Decrypt(encrypted, identity)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := io.ReadAll(io.LimitReader(decrypted, encryptedKeyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(payloadBytes) > encryptedKeyLimit {
		return nil, errors.New("encrypted signing key payload is too large")
	}
	var payload encryptedKeyPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	if payload.Version != encryptedKeyVersion {
		return nil, fmt.Errorf("unsupported signing key version %d", payload.Version)
	}
	if payload.DeviceID == "" || len(payload.Seed) != ed25519.SeedSize {
		return nil, errors.New("invalid signing key payload")
	}
	private := ed25519.NewKeyFromSeed(payload.Seed)
	for i := range payload.Seed {
		payload.Seed[i] = 0
	}
	return &DeviceKey{ID: payload.DeviceID, Private: private, Public: private.Public().(ed25519.PublicKey)}, nil
}

func (k *DeviceKey) lock() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.Private {
		k.Private[i] = 0
	}
	k.Private = nil
	k.Public = nil
}

// privateCopy gives a short-lived signing copy while coordinating auto-lock.
// Go still cannot guarantee erasure of this returned copy.
func (k *DeviceKey) privateCopy() (ed25519.PrivateKey, error) {
	if k == nil {
		return nil, errors.New("signing key is locked")
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if len(k.Private) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is locked")
	}
	return append(ed25519.PrivateKey(nil), k.Private...), nil
}

func (k *DeviceKey) publicKeyBytes() ed25519.PublicKey {
	if k == nil {
		return nil
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if len(k.Public) != ed25519.PublicKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), k.Public...)
}

func (k *DeviceKey) publicKeyText() string {
	if k == nil {
		return ""
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if len(k.Public) != ed25519.PublicKeySize {
		return ""
	}
	return base64.StdEncoding.EncodeToString(k.Public)
}
