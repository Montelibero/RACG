package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Lookup recovers a submission by its original nonce, even after its delivery
// deadline. A fresh challenge binds the server's response to this inspection.
type Lookup struct {
	Version         int    `json:"version"`
	ServerID        string `json:"server_id"`
	ClientID        string `json:"client_id"`
	SubmissionNonce []byte `json:"submission_nonce"`
	Challenge       []byte `json:"challenge"`
	ValidUntil      string `json:"valid_until"`
}
type SignedLookup struct {
	Lookup    Lookup `json:"lookup"`
	Signature []byte `json:"signature"`
}
type LookupResult struct {
	LookupSHA256 string         `json:"lookup_sha256"`
	Found        bool           `json:"found"`
	Request      *SignedRequest `json:"request,omitempty"`
	Status       string         `json:"status,omitempty"`
}
type SignedLookupResult struct {
	Result    LookupResult `json:"result"`
	Signature []byte       `json:"signature"`
}

func NewLookup(serverID, clientID string, nonce []byte, until time.Time) (Lookup, error) {
	q := Lookup{Version: Version, ServerID: serverID, ClientID: clientID, SubmissionNonce: append([]byte(nil), nonce...), Challenge: make([]byte, 32), ValidUntil: until.UTC().Format(time.RFC3339Nano)}
	if _, err := rand.Read(q.Challenge); err != nil {
		return Lookup{}, err
	}
	if err := validateLookup(q); err != nil {
		return Lookup{}, err
	}
	return q, nil
}
func validateLookup(q Lookup) error {
	if q.Version != Version || q.ServerID == "" || q.ClientID == "" || len(q.SubmissionNonce) != 32 || len(q.Challenge) != 32 {
		return errors.New("invalid lookup identity or challenge")
	}
	if _, err := time.Parse(time.RFC3339Nano, q.ValidUntil); err != nil {
		return errors.New("invalid lookup validity")
	}
	return nil
}
func SignLookup(q Lookup, key ed25519.PrivateKey) (SignedLookup, error) {
	if err := validateLookup(q); err != nil {
		return SignedLookup{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedLookup{}, errors.New("invalid agent signing key")
	}
	q.SubmissionNonce = append([]byte(nil), q.SubmissionNonce...)
	q.Challenge = append([]byte(nil), q.Challenge...)
	data, err := message("lookup", q)
	if err != nil {
		return SignedLookup{}, err
	}
	return SignedLookup{Lookup: q, Signature: ed25519.Sign(key, data)}, nil
}
func VerifyLookup(s SignedLookup, serverID, clientID string, key ed25519.PublicKey, now time.Time) error {
	q := s.Lookup
	if err := validateLookup(q); err != nil {
		return err
	}
	if q.ServerID != serverID || q.ClientID != clientID {
		return errors.New("lookup identity mismatch")
	}
	data, err := message("lookup", q)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, s.Signature) {
		return errors.New("invalid lookup signature")
	}
	until, _ := time.Parse(time.RFC3339Nano, q.ValidUntil)
	if !now.Before(until) {
		return errors.New("lookup expired")
	}
	return nil
}
func lookupDigest(q Lookup) (string, error) {
	if err := validateLookup(q); err != nil {
		return "", err
	}
	data, err := message("lookup", q)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// SignLookupResult signs both found and not-found outcomes. Without this,
// an untrusted broker could claim a submitted operation never reached authority.
func SignLookupResult(q Lookup, request *SignedRequest, status string, key ed25519.PrivateKey) (SignedLookupResult, error) {
	digest, err := lookupDigest(q)
	if err != nil {
		return SignedLookupResult{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedLookupResult{}, errors.New("invalid server signing key")
	}
	result := LookupResult{LookupSHA256: digest}
	if request != nil {
		copy := *request
		copy.Request.Operation = append([]byte(nil), request.Request.Operation...)
		copy.Request.Challenge = append([]byte(nil), request.Request.Challenge...)
		copy.Signature = append([]byte(nil), request.Signature...)
		result.Found = true
		result.Request = &copy
		result.Status = status
	} else if status != "" {
		return SignedLookupResult{}, errors.New("missing request for lookup status")
	}
	data, err := message("lookup-result", result)
	if err != nil {
		return SignedLookupResult{}, err
	}
	return SignedLookupResult{Result: result, Signature: ed25519.Sign(key, data)}, nil
}

// VerifyLookupResult authenticates content and freshness against the exact
// locally generated lookup, using the SSH-pinned server key. Status is a
// snapshot, not a promise that a running operation can no longer change.
func VerifyLookupResult(q Lookup, s SignedLookupResult, key ed25519.PublicKey, now time.Time) error {
	digest, err := lookupDigest(q)
	if err != nil {
		return err
	}
	if s.Result.LookupSHA256 != digest {
		return errors.New("lookup response mismatch")
	}
	until, _ := time.Parse(time.RFC3339Nano, q.ValidUntil)
	if !now.Before(until) {
		return errors.New("lookup response expired")
	}
	data, err := message("lookup-result", s.Result)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, s.Signature) {
		return errors.New("invalid lookup response signature")
	}
	if !s.Result.Found {
		if s.Result.Request != nil || s.Result.Status != "" {
			return errors.New("inconsistent absent lookup response")
		}
		return nil
	}
	if s.Result.Request == nil || s.Result.Status == "" {
		return errors.New("incomplete lookup response")
	}
	if s.Result.Request.Request.ClientID != q.ClientID {
		return errors.New("lookup request owner mismatch")
	}
	return VerifyRequest(*s.Result.Request, q.ServerID, key)
}
