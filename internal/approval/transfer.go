package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// StagedUpload authenticates authority-owned immutable bytes. Data is
// transported separately, while the signature binds its size and SHA-256.
type StagedUpload struct {
	Version    int    `json:"version"`
	ServerID   string `json:"server_id"`
	ClientID   string `json:"client_id"`
	UploadID   string `json:"upload_id"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	ValidUntil string `json:"valid_until"`
}

type SignedStagedUpload struct {
	Upload    StagedUpload `json:"upload"`
	Signature []byte       `json:"signature"`
}

func NewStagedUpload(serverID, clientID string, data []byte, validUntil time.Time) (StagedUpload, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return StagedUpload{}, err
	}
	upload := StagedUpload{
		Version:    Version,
		ServerID:   serverID,
		ClientID:   clientID,
		UploadID:   hex.EncodeToString(idBytes),
		Size:       int64(len(data)),
		SHA256:     SHA256Hex(data),
		ValidUntil: validUntil.UTC().Format(time.RFC3339Nano),
	}
	if err := validateStagedUpload(upload); err != nil {
		return StagedUpload{}, err
	}
	return upload, nil
}

func validateStagedUpload(upload StagedUpload) error {
	if upload.Version != Version || upload.ServerID == "" || upload.ClientID == "" || len(upload.UploadID) != 32 {
		return errors.New("invalid staged upload identity")
	}
	if _, err := hex.DecodeString(upload.UploadID); err != nil {
		return errors.New("invalid staged upload ID")
	}
	if upload.Size < 0 || len(upload.SHA256) != 64 {
		return errors.New("invalid staged upload metadata")
	}
	if _, err := hex.DecodeString(upload.SHA256); err != nil {
		return errors.New("invalid staged upload digest")
	}
	if _, err := time.Parse(time.RFC3339Nano, upload.ValidUntil); err != nil {
		return errors.New("invalid staged upload validity")
	}
	return nil
}

func SignStagedUpload(upload StagedUpload, key ed25519.PrivateKey) (SignedStagedUpload, error) {
	if err := validateStagedUpload(upload); err != nil {
		return SignedStagedUpload{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedStagedUpload{}, errors.New("invalid agent signing key")
	}
	data, err := message("staged-upload", upload)
	if err != nil {
		return SignedStagedUpload{}, err
	}
	return SignedStagedUpload{Upload: upload, Signature: ed25519.Sign(key, data)}, nil
}

func VerifyStagedUpload(upload SignedStagedUpload, serverID, clientID string, key ed25519.PublicKey, data []byte, now time.Time) error {
	if err := validateStagedUpload(upload.Upload); err != nil {
		return err
	}
	if upload.Upload.ServerID != serverID || upload.Upload.ClientID != clientID {
		return errors.New("staged upload identity mismatch")
	}
	if int64(len(data)) != upload.Upload.Size || SHA256Hex(data) != upload.Upload.SHA256 {
		return errors.New("staged upload bytes mismatch")
	}
	data, err := message("staged-upload", upload.Upload)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, upload.Signature) {
		return errors.New("invalid staged upload signature")
	}
	until, _ := time.Parse(time.RFC3339Nano, upload.Upload.ValidUntil)
	if !now.Before(until) {
		return errors.New("staged upload expired")
	}
	return nil
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
