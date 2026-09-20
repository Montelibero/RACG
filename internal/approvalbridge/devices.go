package approvalbridge

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"

	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type storedDevice struct {
	PublicKey []byte `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

type deviceFile struct {
	Devices map[string]storedDevice `json:"devices"`
}

type DeviceRegistry struct {
	path string
	mu   sync.Mutex
}

func NewDeviceRegistry(path string) *DeviceRegistry {
	return &DeviceRegistry{path: path}
}

func (r *DeviceRegistry) Pair(code, deviceID string, publicKey []byte) error {
	expected := os.Getenv("RACG_PHONE_PAIRING_CODE")
	if expected == "" || code != expected {
		return errors.New("invalid pairing code")
	}
	if deviceID == "" || len(publicKey) == 0 {
		return errors.New("device identity and public key required")
	}
	if _, err := x509.ParsePKIXPublicKey(publicKey); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	devices, err := r.load()
	if err != nil {
		return err
	}
	if _, exists := devices.Devices[deviceID]; exists {
		return errors.New("device already paired")
	}
	devices.Devices[deviceID] = storedDevice{
		PublicKey: append([]byte(nil), publicKey...),
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	return r.save(devices)
}

func (r *DeviceRegistry) PublicKey(deviceID string) (crypto.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	devices, err := r.load()
	if err != nil {
		return nil, err
	}
	device, ok := devices.Devices[deviceID]
	if !ok {
		return nil, errors.New("unknown phone device")
	}
	return x509.ParsePKIXPublicKey(device.PublicKey)
}

func (r *DeviceRegistry) load() (deviceFile, error) {
	devices := deviceFile{Devices: map[string]storedDevice{}}
	b, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return devices, nil
	}
	if err != nil {
		return deviceFile{}, err
	}
	if err := json.Unmarshal(b, &devices); err != nil {
		return deviceFile{}, err
	}
	if devices.Devices == nil {
		devices.Devices = map[string]storedDevice{}
	}
	return devices, nil
}

func (r *DeviceRegistry) save(devices deviceFile) error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.path), ".racg-phone-devices-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, r.path)
}

func verifyPhoneDecisionSignature(publicKey crypto.PublicKey, message, signature []byte) error {
	public, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("phone device key is not ECDSA")
	}
	hash := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(public, hash[:], signature) {
		return errors.New("invalid phone decision signature")
	}
	return nil
}

type PhoneServer struct {
	code string
}

func NewPhoneServer(pairingCode string) *PhoneServer {
	return &PhoneServer{code: pairingCode}
}

func (s *PhoneServer) Pair(code, deviceID string, publicKey []byte) error {
	if subtle.ConstantTimeCompare([]byte(code), []byte(s.code)) != 1 {
		return errors.New("invalid pairing code")
	}
	if deviceID == "" || len(publicKey) == 0 {
		return errors.New("device identity and public key required")
	}
	if _, err := x509.ParsePKIXPublicKey(publicKey); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	return nil
}

func (s *PhoneServer) Challenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
