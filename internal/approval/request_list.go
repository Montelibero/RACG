package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// RequestList is a device-signed read-only poll for the authority's pending
// approval queue. It authorizes inspection only; it never approves or executes.
type RequestList struct {
	Version    int    `json:"version"`
	ServerID   string `json:"server_id"`
	DeviceID   string `json:"device_id"`
	Challenge  []byte `json:"challenge"`
	ValidUntil string `json:"valid_until"`
}

type SignedRequestList struct {
	List      RequestList `json:"list"`
	Signature []byte      `json:"signature"`
}

type RequestListResult struct {
	ListSHA256 string          `json:"list_sha256"`
	Requests   []SignedRequest `json:"requests"`
}

type SignedRequestListResult struct {
	Result    RequestListResult `json:"result"`
	Signature []byte            `json:"signature"`
}

func NewRequestList(serverID, deviceID string, until time.Time) (RequestList, error) {
	list := RequestList{
		Version:    Version,
		ServerID:   serverID,
		DeviceID:   deviceID,
		Challenge:  make([]byte, 32),
		ValidUntil: until.UTC().Format(time.RFC3339Nano),
	}
	if _, err := rand.Read(list.Challenge); err != nil {
		return RequestList{}, err
	}
	if err := validateRequestList(list); err != nil {
		return RequestList{}, err
	}
	return list, nil
}

func validateRequestList(list RequestList) error {
	if list.Version != Version || list.ServerID == "" || list.DeviceID == "" || len(list.Challenge) != 32 {
		return errors.New("invalid request list identity")
	}
	if _, err := time.Parse(time.RFC3339Nano, list.ValidUntil); err != nil {
		return errors.New("invalid request list validity")
	}
	return nil
}

func SignRequestList(list RequestList, key ed25519.PrivateKey) (SignedRequestList, error) {
	if err := validateRequestList(list); err != nil {
		return SignedRequestList{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedRequestList{}, errors.New("invalid device signing key")
	}
	list.Challenge = append([]byte(nil), list.Challenge...)
	data, err := message("request-list", list)
	if err != nil {
		return SignedRequestList{}, err
	}
	return SignedRequestList{List: list, Signature: ed25519.Sign(key, data)}, nil
}

func VerifyRequestList(s SignedRequestList, serverID, deviceID string, key ed25519.PublicKey, now time.Time) error {
	list := s.List
	if err := validateRequestList(list); err != nil {
		return err
	}
	if list.ServerID != serverID || list.DeviceID != deviceID {
		return errors.New("request list identity mismatch")
	}
	data, err := message("request-list", list)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, s.Signature) {
		return errors.New("invalid request list signature")
	}
	until, _ := time.Parse(time.RFC3339Nano, list.ValidUntil)
	if !now.Before(until) {
		return errors.New("request list expired")
	}
	return nil
}

func requestListDigest(list RequestList) (string, error) {
	if err := validateRequestList(list); err != nil {
		return "", err
	}
	data, err := message("request-list", list)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// SignRequestListResult signs an empty and non-empty snapshot. Without a signed
// empty result, a broker can hide pending work by claiming the queue is empty.
func SignRequestListResult(list RequestList, requests []SignedRequest, key ed25519.PrivateKey) (SignedRequestListResult, error) {
	digest, err := requestListDigest(list)
	if err != nil {
		return SignedRequestListResult{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return SignedRequestListResult{}, errors.New("invalid authority signing key")
	}
	result := RequestListResult{ListSHA256: digest, Requests: []SignedRequest{}}
	for i := range requests {
		if requests[i].Request.ServerID != list.ServerID {
			return SignedRequestListResult{}, errors.New("request list server mismatch")
		}
		if err := VerifyRequest(requests[i], list.ServerID, key.Public().(ed25519.PublicKey)); err != nil {
			return SignedRequestListResult{}, err
		}
		for previous := 0; previous < i; previous++ {
			if requests[i].Request.RequestID == requests[previous].Request.RequestID {
				return SignedRequestListResult{}, errors.New("duplicate request in list")
			}
		}
		copy := requests[i]
		copy.Request.Operation = append([]byte(nil), requests[i].Request.Operation...)
		copy.Request.Challenge = append([]byte(nil), requests[i].Request.Challenge...)
		copy.Signature = append([]byte(nil), requests[i].Signature...)
		result.Requests = append(result.Requests, copy)
	}
	data, err := message("request-list-result", result)
	if err != nil {
		return SignedRequestListResult{}, err
	}
	return SignedRequestListResult{Result: result, Signature: ed25519.Sign(key, data)}, nil
}

// VerifyRequestListResult authenticates a point-in-time snapshot using the
// SSH-pinned server key. Pending does not imply safe; it may become denied or
// consumed before the operator acts.
func VerifyRequestListResult(list RequestList, signed SignedRequestListResult, key ed25519.PublicKey, now time.Time) error {
	digest, err := requestListDigest(list)
	if err != nil {
		return err
	}
	if signed.Result.ListSHA256 != digest {
		return errors.New("request list response mismatch")
	}
	until, _ := time.Parse(time.RFC3339Nano, list.ValidUntil)
	if !now.Before(until) {
		return errors.New("request list response expired")
	}
	data, err := message("request-list-result", signed.Result)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, signed.Signature) {
		return errors.New("invalid request list response signature")
	}
	seen := make(map[string]struct{}, len(signed.Result.Requests))
	for i := range signed.Result.Requests {
		request := &signed.Result.Requests[i]
		if err := VerifyRequest(*request, list.ServerID, key); err != nil {
			return err
		}
		if _, exists := seen[request.Request.RequestID]; exists {
			return errors.New("duplicate request in response")
		}
		seen[request.Request.RequestID] = struct{}{}
	}
	return nil
}
