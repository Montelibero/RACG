package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Cancellation is the agent's signed request to stop a not-yet-dispatched
// operation. It can never claim that a running job was killed.
type Cancellation struct {
	Version         int    `json:"version"`
	ServerID        string `json:"server_id"`
	ClientID        string `json:"client_id"`
	RequestID       string `json:"request_id"`
	SubmissionNonce []byte `json:"submission_nonce"`
	Challenge       []byte `json:"challenge"`
	ValidUntil      string `json:"valid_until"`
}

type SignedCancellation struct {
	Cancellation Cancellation `json:"cancellation"`
	Signature    []byte       `json:"signature"`
}

type CancellationResult struct {
	CancellationSHA256 string `json:"cancellation_sha256"`
	RequestID          string `json:"request_id"`
	Status             string `json:"status"`
	Canceled           bool   `json:"canceled"`
	Challenge          []byte `json:"challenge"`
}

type SignedCancellationResult struct {
	Result    CancellationResult `json:"result"`
	Signature []byte             `json:"signature"`
}

func NewCancellation(serverID, clientID, requestID string, nonce []byte, until time.Time) (Cancellation, error) {
	cancellation := Cancellation{
		Version:         Version,
		ServerID:        serverID,
		ClientID:        clientID,
		RequestID:       requestID,
		SubmissionNonce: append([]byte(nil), nonce...),
		Challenge:       make([]byte, 32),
		ValidUntil:      until.UTC().Format(time.RFC3339Nano),
	}
	if _, err := rand.Read(cancellation.Challenge); err != nil {
		return Cancellation{}, err
	}
	if err := validateCancellation(cancellation); err != nil {
		return Cancellation{}, err
	}
	return cancellation, nil
}

func validateCancellation(c Cancellation) error {
	if c.Version != Version || c.ServerID == "" || c.ClientID == "" || c.RequestID == "" || len(c.SubmissionNonce) != 32 || len(c.Challenge) != 32 {
		return errors.New("invalid cancellation identity")
	}
	if _, err := time.Parse(time.RFC3339Nano, c.ValidUntil); err != nil {
		return errors.New("invalid cancellation validity")
	}
	return nil
}

func SignCancellation(c Cancellation, key ed25519.PrivateKey) (SignedCancellation, error) {
	if err := validateCancellation(c); err != nil {
		return SignedCancellation{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedCancellation{}, errors.New("invalid agent signing key")
	}
	c.SubmissionNonce = append([]byte(nil), c.SubmissionNonce...)
	c.Challenge = append([]byte(nil), c.Challenge...)
	data, err := message("cancellation", c)
	if err != nil {
		return SignedCancellation{}, err
	}
	return SignedCancellation{Cancellation: c, Signature: ed25519.Sign(key, data)}, nil
}

func VerifyCancellation(s SignedCancellation, serverID, clientID, requestID string, key ed25519.PublicKey, now time.Time) error {
	c := s.Cancellation
	if err := validateCancellation(c); err != nil {
		return err
	}
	if c.ServerID != serverID || c.ClientID != clientID || c.RequestID != requestID {
		return errors.New("cancellation identity mismatch")
	}
	data, err := message("cancellation", c)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, s.Signature) {
		return errors.New("invalid cancellation signature")
	}
	until, _ := time.Parse(time.RFC3339Nano, c.ValidUntil)
	if !now.Before(until) {
		return errors.New("cancellation expired")
	}
	return nil
}

func cancellationDigest(c Cancellation) (string, error) {
	if err := validateCancellation(c); err != nil {
		return "", err
	}
	data, err := message("cancellation", c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// SignCancellationResult signs both success and refusal outcomes. Canceled=true
// means durable pre-dispatch cancellation; false means the authority observed a
// different state and the caller must inspect that state.
func SignCancellationResult(c Cancellation, status string, canceled bool, key ed25519.PrivateKey) (SignedCancellationResult, error) {
	digest, err := cancellationDigest(c)
	if err != nil {
		return SignedCancellationResult{}, err
	}
	if status == "" {
		return SignedCancellationResult{}, errors.New("missing cancellation status")
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedCancellationResult{}, errors.New("invalid authority signing key")
	}
	result := CancellationResult{
		CancellationSHA256: digest,
		RequestID:          c.RequestID,
		Status:             status,
		Canceled:           canceled,
		Challenge:          append([]byte(nil), c.Challenge...),
	}
	data, err := message("cancellation-result", result)
	if err != nil {
		return SignedCancellationResult{}, err
	}
	return SignedCancellationResult{Result: result, Signature: ed25519.Sign(key, data)}, nil
}

func VerifyCancellationResult(c Cancellation, s SignedCancellationResult, key ed25519.PublicKey, now time.Time) error {
	digest, err := cancellationDigest(c)
	if err != nil {
		return err
	}
	result := s.Result
	until, _ := time.Parse(time.RFC3339Nano, c.ValidUntil)
	switch {
	case result.CancellationSHA256 != digest:
		err = errors.New("cancellation response mismatch")
	case result.RequestID != c.RequestID || !bytes.Equal(result.Challenge, c.Challenge):
		err = errors.New("cancellation response identity mismatch")
	case result.Status == "":
		err = errors.New("cancellation response missing status")
	case result.Canceled && result.Status != "CANCELED":
		err = errors.New("inconsistent cancellation response")
	case !result.Canceled && result.Status == "CANCELED":
		err = errors.New("inconsistent cancellation response")
	case !now.Before(until):
		err = errors.New("cancellation response expired")
	}
	if err != nil {
		return err
	}
	data, err := message("cancellation-result", result)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, s.Signature) {
		return errors.New("invalid cancellation response signature")
	}
	return nil
}
