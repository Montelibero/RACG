package serviceagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

const (
	keyFileVersion = 1
	keyFileLimit   = 4096
)

var keyWorkFactor = 18

type Key struct {
	ClientID string
	Private  ed25519.PrivateKey
	Public   ed25519.PublicKey
}

type encryptedKeyPayload struct {
	Version  int    `json:"version"`
	ClientID string `json:"client_id"`
	Seed     []byte `json:"seed"`
}

func GenerateKey(clientID string) (*Key, error) {
	if clientID == "" {
		return nil, errors.New("client ID required")
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	private := ed25519.NewKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	return &Key{ClientID: clientID, Private: private, Public: private.Public().(ed25519.PublicKey)}, nil
}

func SaveKey(path string, key *Key, passphrase string) error {
	if key == nil || key.ClientID == "" || len(key.Private) != ed25519.PrivateKeySize {
		return errors.New("valid service agent key required")
	}
	if path == "" {
		return errors.New("key path required")
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	recipient.SetWorkFactor(keyWorkFactor)
	payload, err := json.Marshal(encryptedKeyPayload{
		Version:  keyFileVersion,
		ClientID: key.ClientID,
		Seed:     key.Private.Seed(),
	})
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("agent key already exists: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
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
	cleanup = false
	return nil
}

func LoadKey(path, passphrase string) (*Key, error) {
	if path == "" {
		return nil, errors.New("key path required")
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	identity.SetMaxWorkFactor(keyWorkFactor)
	encrypted, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer encrypted.Close()
	decrypted, err := age.Decrypt(encrypted, identity)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := io.ReadAll(io.LimitReader(decrypted, keyFileLimit+1))
	if err != nil {
		return nil, err
	}
	if len(payloadBytes) > keyFileLimit {
		return nil, errors.New("agent key payload is too large")
	}
	var payload encryptedKeyPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("decode agent key: %w", err)
	}
	if payload.Version != keyFileVersion || payload.ClientID == "" || len(payload.Seed) != ed25519.SeedSize {
		return nil, errors.New("invalid agent key payload")
	}
	private := ed25519.NewKeyFromSeed(payload.Seed)
	for i := range payload.Seed {
		payload.Seed[i] = 0
	}
	return &Key{ClientID: payload.ClientID, Private: private, Public: private.Public().(ed25519.PublicKey)}, nil
}

func (k *Key) PublicKeyBase64() string {
	if k == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(k.Public)
}

func (k *Key) privateCopy() (ed25519.PrivateKey, error) {
	if k == nil || len(k.Private) != ed25519.PrivateKeySize {
		return nil, errors.New("agent key is locked or invalid")
	}
	return append(ed25519.PrivateKey(nil), k.Private...), nil
}
