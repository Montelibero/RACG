package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"
)

// Submission authenticates an agent independently of the network broker.
// Agent credentials authorize submission, never approval. Service submissions
// do not carry a broker-supplied session label.
type Submission struct {
	Version    int    `json:"version"`
	ServerID   string `json:"server_id"`
	ClientID   string `json:"client_id"`
	Nonce      []byte `json:"nonce"`
	Operation  []byte `json:"operation"`
	ValidUntil string `json:"valid_until"`
}

type SignedSubmission struct {
	Submission Submission `json:"submission"`
	Signature  []byte     `json:"signature"`
}

// NewSubmission creates a retry identity for one operation. Retry by resending
// the same signed submission, not by generating another nonce. Delivery expiry
// is chosen by the caller and does not expire the enrolled agent key.
func NewSubmission(serverID, clientID string, operation []byte, validUntil time.Time) (Submission, error) {
	s := Submission{Version: Version, ServerID: serverID, ClientID: clientID, Operation: append([]byte(nil), operation...), Nonce: make([]byte, 32), ValidUntil: validUntil.UTC().Format(time.RFC3339Nano)}
	if _, err := rand.Read(s.Nonce); err != nil {
		return Submission{}, err
	}
	if err := validateSubmission(s); err != nil {
		return Submission{}, err
	}
	return s, nil
}

func validateSubmission(s Submission) error {
	if s.Version != Version || s.ServerID == "" || s.ClientID == "" {
		return errors.New("invalid submission identity or version")
	}
	if len(s.Nonce) != 32 {
		return errors.New("invalid submission nonce")
	}
	if !json.Valid(s.Operation) {
		return errors.New("operation must contain valid JSON")
	}
	if _, err := time.Parse(time.RFC3339Nano, s.ValidUntil); err != nil {
		return errors.New("invalid submission validity")
	}
	return nil
}

func SignSubmission(s Submission, key ed25519.PrivateKey) (SignedSubmission, error) {
	if err := validateSubmission(s); err != nil {
		return SignedSubmission{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedSubmission{}, errors.New("invalid agent signing key")
	}
	s.Operation = append([]byte(nil), s.Operation...)
	s.Nonce = append([]byte(nil), s.Nonce...)
	data, err := message("submission", s)
	if err != nil {
		return SignedSubmission{}, err
	}
	return SignedSubmission{Submission: s, Signature: ed25519.Sign(key, data)}, nil
}

func VerifySubmission(s SignedSubmission, serverID, clientID string, key ed25519.PublicKey, now time.Time) error {
	if err := validateSubmission(s.Submission); err != nil {
		return err
	}
	if s.Submission.ServerID != serverID || s.Submission.ClientID != clientID {
		return errors.New("submission identity mismatch")
	}
	data, err := message("submission", s.Submission)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, s.Signature) {
		return errors.New("invalid agent signature")
	}
	until, _ := time.Parse(time.RFC3339Nano, s.Submission.ValidUntil)
	if !now.Before(until) {
		return errors.New("submission expired")
	}
	return nil
}
