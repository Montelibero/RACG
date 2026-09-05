// Package approval defines the signed service-mode approval protocol.
// It does not expose the interactive UI's unsigned decision methods.
package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const Version = 1

// Request carries exact immutable operation bytes. JSON encodes byte slices as
// base64, avoiding re-interpretation or reserialization of operation JSON while
// signing. The authority must execute these same bytes after authorization.
type Request struct {
	Version   int    `json:"version"`
	ServerID  string `json:"server_id"`
	RequestID string `json:"request_id"`
	ClientID  string `json:"client_id"`
	SessionID string `json:"session_id"`
	Operation []byte `json:"operation"`
	Challenge []byte `json:"challenge"`
}

type SignedRequest struct {
	Request   Request `json:"request"`
	Signature []byte  `json:"signature"`
}

// Grant separates the exact rule scope from its lifetime. Scope is interpreted
// and matched by the authority, never by an untrusted broker's assertion.
type Grant struct {
	Scope     []byte `json:"scope"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type Decision struct {
	Version       int    `json:"version"`
	RequestSHA256 string `json:"request_sha256"`
	DeviceID      string `json:"device_id"`
	Action        string `json:"action"`
	Grant         *Grant `json:"grant,omitempty"`
	ValidUntil    string `json:"valid_until"`
}

type SignedDecision struct {
	Decision  Decision `json:"decision"`
	Signature []byte   `json:"signature"`
}

func NewRequest(serverID, requestID, clientID, sessionID string, operation []byte) (Request, error) {
	r := Request{Version: Version, ServerID: serverID, RequestID: requestID, ClientID: clientID, SessionID: sessionID, Operation: append([]byte(nil), operation...), Challenge: make([]byte, 32)}
	if _, err := rand.Read(r.Challenge); err != nil {
		return Request{}, err
	}
	if err := validateRequest(r); err != nil {
		return Request{}, err
	}
	return r, nil
}

func validateRequest(r Request) error {
	if r.Version != Version {
		return errors.New("unsupported approval protocol version")
	}
	if r.ServerID == "" || r.RequestID == "" || r.ClientID == "" {
		return errors.New("missing request identity")
	}
	if len(r.Challenge) != 32 {
		return errors.New("invalid approval challenge")
	}
	if !json.Valid(r.Operation) {
		return errors.New("operation must contain valid JSON")
	}
	return nil
}

func message(domain string, value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append([]byte("RACG/approval/v1/"+domain+"\x00"), b...), nil
}

func RequestDigest(r Request) (string, error) {
	if err := validateRequest(r); err != nil {
		return "", err
	}
	b, err := message("request", r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func SignRequest(r Request, key ed25519.PrivateKey) (SignedRequest, error) {
	if err := validateRequest(r); err != nil {
		return SignedRequest{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedRequest{}, errors.New("invalid signing key")
	}
	r.Operation = append([]byte(nil), r.Operation...)
	r.Challenge = append([]byte(nil), r.Challenge...)
	b, err := message("request", r)
	if err != nil {
		return SignedRequest{}, err
	}
	return SignedRequest{Request: r, Signature: ed25519.Sign(key, b)}, nil
}

// VerifyRequest authenticates the display content against the enrolled server.
func VerifyRequest(s SignedRequest, serverID string, key ed25519.PublicKey) error {
	if err := validateRequest(s.Request); err != nil {
		return err
	}
	if s.Request.ServerID != serverID {
		return errors.New("server identity mismatch")
	}
	b, err := message("request", s.Request)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, b, s.Signature) {
		return errors.New("invalid server signature")
	}
	return nil
}

func SignDecision(r Request, deviceID, action string, grant *Grant, validUntil time.Time, key ed25519.PrivateKey) (SignedDecision, error) {
	digest, err := RequestDigest(r)
	if err != nil {
		return SignedDecision{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedDecision{}, errors.New("invalid signing key")
	}
	if grant != nil {
		g := *grant
		g.Scope = append([]byte(nil), grant.Scope...)
		grant = &g
	}
	d := Decision{Version: Version, RequestSHA256: digest, DeviceID: deviceID, Action: action, Grant: grant, ValidUntil: validUntil.UTC().Format(time.RFC3339Nano)}
	if err := validateDecision(d); err != nil {
		return SignedDecision{}, err
	}
	b, err := message("decision", d)
	if err != nil {
		return SignedDecision{}, err
	}
	return SignedDecision{Decision: d, Signature: ed25519.Sign(key, b)}, nil
}

func validateDecision(d Decision) error {
	if d.Version != Version || d.DeviceID == "" {
		return errors.New("invalid decision identity or version")
	}
	if _, err := time.Parse(time.RFC3339Nano, d.ValidUntil); err != nil {
		return fmt.Errorf("invalid decision validity: %w", err)
	}
	switch d.Action {
	case "DENY", "ALLOW_ONCE":
		if d.Grant != nil {
			return errors.New("one-shot decision cannot include a reusable grant")
		}
	case "ALLOW_SESSION", "ALLOW_ALWAYS", "ALLOW_UNTIL":
		if d.Grant == nil || !json.Valid(d.Grant.Scope) {
			return errors.New("reusable decision requires a rule scope")
		}
		if d.Action == "ALLOW_UNTIL" {
			if _, err := time.Parse(time.RFC3339Nano, d.Grant.ExpiresAt); err != nil {
				return errors.New("timed grant requires a valid expiry")
			}
		} else if d.Grant.ExpiresAt != "" {
			return errors.New("expiry requires ALLOW_UNTIL")
		}
	default:
		return errors.New("unknown approval action")
	}
	return nil
}

// VerifyDecision checks authenticity and binding only. The authority must also
// check current device enrollment/revocation, validate scope semantics and
// durably consume the pending request exactly once before dispatching execution.
func VerifyDecision(r Request, s SignedDecision, deviceID string, key ed25519.PublicKey, now time.Time) error {
	if err := validateDecision(s.Decision); err != nil {
		return err
	}
	if s.Decision.DeviceID != deviceID {
		return errors.New("device identity mismatch")
	}
	digest, err := RequestDigest(r)
	if err != nil {
		return err
	}
	if s.Decision.RequestSHA256 != digest {
		return errors.New("request digest mismatch")
	}
	b, err := message("decision", s.Decision)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, b, s.Signature) {
		return errors.New("invalid device signature")
	}
	until, _ := time.Parse(time.RFC3339Nano, s.Decision.ValidUntil)
	if !now.Before(until) {
		return errors.New("decision expired")
	}
	if s.Decision.Grant != nil && s.Decision.Action == "ALLOW_UNTIL" {
		expires, _ := time.Parse(time.RFC3339Nano, s.Decision.Grant.ExpiresAt)
		if !now.Before(expires) {
			return errors.New("grant expired")
		}
	}
	return nil
}
