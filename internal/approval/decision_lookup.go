package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// DecisionLookup recovers the authoritative state of a request after a lost
// delivery receipt. It is signed by an enrolled approver device and is
// read-only: it never submits, approves, cancels or executes a request.
type DecisionLookup struct {
	Version       int    `json:"version"`
	ServerID      string `json:"server_id"`
	DeviceID      string `json:"device_id"`
	RequestID     string `json:"request_id"`
	RequestSHA256 string `json:"request_sha256"`
	Challenge     []byte `json:"challenge"`
	ValidUntil    string `json:"valid_until"`
}

type SignedDecisionLookup struct {
	Lookup    DecisionLookup `json:"lookup"`
	Signature []byte         `json:"signature"`
}

type DecisionLookupResult struct {
	LookupSHA256     string         `json:"lookup_sha256"`
	Found            bool           `json:"found"`
	Request          *SignedRequest `json:"request,omitempty"`
	Status           string         `json:"status,omitempty"`
	DecisionAction   string         `json:"decision_action,omitempty"`
	DecisionDeviceID string         `json:"decision_device_id,omitempty"`
}

type SignedDecisionLookupResult struct {
	Result    DecisionLookupResult `json:"result"`
	Signature []byte               `json:"signature"`
}

func NewDecisionLookup(serverID, deviceID string, request Request, until time.Time) (DecisionLookup, error) {
	digest, err := RequestDigest(request)
	if err != nil {
		return DecisionLookup{}, err
	}
	q := DecisionLookup{
		Version:       Version,
		ServerID:      serverID,
		DeviceID:      deviceID,
		RequestID:     request.RequestID,
		RequestSHA256: digest,
		Challenge:     make([]byte, 32),
		ValidUntil:    until.UTC().Format(time.RFC3339Nano),
	}
	if _, err := rand.Read(q.Challenge); err != nil {
		return DecisionLookup{}, err
	}
	if err := validateDecisionLookup(q); err != nil {
		return DecisionLookup{}, err
	}
	return q, nil
}

func validateDecisionLookup(q DecisionLookup) error {
	if q.Version != Version || q.ServerID == "" || q.DeviceID == "" || q.RequestID == "" {
		return errors.New("invalid decision lookup identity")
	}
	if len(q.Challenge) != 32 {
		return errors.New("invalid decision lookup challenge")
	}
	if len(q.RequestSHA256) != 64 {
		return errors.New("invalid decision lookup request digest")
	}
	if _, err := hex.DecodeString(q.RequestSHA256); err != nil {
		return errors.New("invalid decision lookup request digest")
	}
	if _, err := time.Parse(time.RFC3339Nano, q.ValidUntil); err != nil {
		return errors.New("invalid decision lookup validity")
	}
	return nil
}

func SignDecisionLookup(q DecisionLookup, key ed25519.PrivateKey) (SignedDecisionLookup, error) {
	if err := validateDecisionLookup(q); err != nil {
		return SignedDecisionLookup{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedDecisionLookup{}, errors.New("invalid device signing key")
	}
	q.Challenge = append([]byte(nil), q.Challenge...)
	data, err := message("decision-lookup", q)
	if err != nil {
		return SignedDecisionLookup{}, err
	}
	return SignedDecisionLookup{Lookup: q, Signature: ed25519.Sign(key, data)}, nil
}

// VerifyDecisionLookupCredentials authenticates the current device, freshness
// and authority binding without requiring the request bytes. A transport can
// use it before deciding whether an unknown request ID may return not-found.
func VerifyDecisionLookupCredentials(s SignedDecisionLookup, serverID, deviceID string, key ed25519.PublicKey, now time.Time) error {
	return VerifyDecisionLookupCredentialsWithKeyType(s, serverID, deviceID, KeyTypeEd25519, key, now)
}

func VerifyDecisionLookupCredentialsWithKeyType(s SignedDecisionLookup, serverID, deviceID, keyType string, key []byte, now time.Time) error {
	q := s.Lookup
	if err := validateDecisionLookup(q); err != nil {
		return err
	}
	if q.ServerID != serverID || q.DeviceID != deviceID {
		return errors.New("decision lookup identity mismatch")
	}
	data, err := message("decision-lookup", q)
	if err != nil {
		return err
	}
	if err := VerifyDeviceKeySignature(keyType, key, data, s.Signature); err != nil {
		return err
	}
	until, _ := time.Parse(time.RFC3339Nano, q.ValidUntil)
	if !now.Before(until) {
		return errors.New("decision lookup expired")
	}
	return nil
}

func VerifyDecisionLookup(s SignedDecisionLookup, serverID, deviceID string, request Request, key ed25519.PublicKey, now time.Time) error {
	return VerifyDecisionLookupWithKeyType(s, serverID, deviceID, KeyTypeEd25519, key, request, now)
}

func VerifyDecisionLookupWithKeyType(s SignedDecisionLookup, serverID, deviceID, keyType string, key []byte, request Request, now time.Time) error {
	if err := VerifyDecisionLookupCredentialsWithKeyType(s, serverID, deviceID, keyType, key, now); err != nil {
		return err
	}
	q := s.Lookup
	digest, err := RequestDigest(request)
	if err != nil {
		return err
	}
	if q.RequestID != request.RequestID || q.RequestSHA256 != digest {
		return errors.New("decision lookup request mismatch")
	}
	return nil
}

func decisionLookupDigest(q DecisionLookup) (string, error) {
	if err := validateDecisionLookup(q); err != nil {
		return "", err
	}
	data, err := message("decision-lookup", q)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// SignDecisionLookupResult signs found and not-found outcomes. Authority ownership
// of this signature lets the approver distinguish absence from broker suppression.
func SignDecisionLookupResult(q DecisionLookup, request *SignedRequest, status string, decisionAction, decisionDeviceID string, key ed25519.PrivateKey) (SignedDecisionLookupResult, error) {
	digest, err := decisionLookupDigest(q)
	if err != nil {
		return SignedDecisionLookupResult{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedDecisionLookupResult{}, errors.New("invalid authority signing key")
	}
	result := DecisionLookupResult{LookupSHA256: digest}
	if request == nil {
		if status != "" || decisionAction != "" || decisionDeviceID != "" {
			return SignedDecisionLookupResult{}, errors.New("missing request for decision lookup status")
		}
		data, err := message("decision-lookup-result", result)
		if err != nil {
			return SignedDecisionLookupResult{}, err
		}
		return SignedDecisionLookupResult{Result: result, Signature: ed25519.Sign(key, data)}, nil
	}
	if status == "" || (decisionAction == "") != (decisionDeviceID == "") {
		return SignedDecisionLookupResult{}, errors.New("inconsistent decision lookup response")
	}
	copy := *request
	copy.Request.Operation = append([]byte(nil), request.Request.Operation...)
	copy.Request.Challenge = append([]byte(nil), request.Request.Challenge...)
	copy.Signature = append([]byte(nil), request.Signature...)
	if err := VerifyRequest(copy, q.ServerID, key.Public().(ed25519.PublicKey)); err != nil {
		return SignedDecisionLookupResult{}, err
	}
	responseDigest, err := RequestDigest(copy.Request)
	if err != nil {
		return SignedDecisionLookupResult{}, err
	}
	if copy.Request.RequestID != q.RequestID || responseDigest != q.RequestSHA256 {
		return SignedDecisionLookupResult{}, errors.New("decision lookup request mismatch")
	}
	result.Found = true
	result.Request = &copy
	result.Status = status
	result.DecisionAction = decisionAction
	result.DecisionDeviceID = decisionDeviceID
	data, err := message("decision-lookup-result", result)
	if err != nil {
		return SignedDecisionLookupResult{}, err
	}
	return SignedDecisionLookupResult{Result: result, Signature: ed25519.Sign(key, data)}, nil
}

// VerifyDecisionLookupResult authenticates a point-in-time snapshot against the
// exact lookup and pinned authority key. It does not imply that a started job
// can still be cancelled or that a terminal result cannot later be inspected.
func VerifyDecisionLookupResult(q DecisionLookup, s SignedDecisionLookupResult, serverKey ed25519.PublicKey, now time.Time) error {
	digest, err := decisionLookupDigest(q)
	if err != nil {
		return err
	}
	if s.Result.LookupSHA256 != digest {
		return errors.New("decision lookup response mismatch")
	}
	until, _ := time.Parse(time.RFC3339Nano, q.ValidUntil)
	if !now.Before(until) {
		return errors.New("decision lookup response expired")
	}
	data, err := message("decision-lookup-result", s.Result)
	if err != nil {
		return err
	}
	if len(serverKey) != ed25519.PublicKeySize || !ed25519.Verify(serverKey, data, s.Signature) {
		return errors.New("invalid decision lookup response signature")
	}
	if !s.Result.Found {
		if s.Result.Request != nil || s.Result.Status != "" || s.Result.DecisionAction != "" || s.Result.DecisionDeviceID != "" {
			return errors.New("inconsistent absent decision lookup response")
		}
		return nil
	}
	if s.Result.Request == nil || s.Result.Status == "" || (s.Result.DecisionAction == "") != (s.Result.DecisionDeviceID == "") {
		return errors.New("incomplete decision lookup response")
	}
	if err := VerifyRequest(*s.Result.Request, q.ServerID, serverKey); err != nil {
		return err
	}
	requestDigest, err := RequestDigest(s.Result.Request.Request)
	if err != nil {
		return err
	}
	if s.Result.Request.Request.RequestID != q.RequestID || requestDigest != q.RequestSHA256 {
		return errors.New("decision lookup response request mismatch")
	}
	return nil
}
