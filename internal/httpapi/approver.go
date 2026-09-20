package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/auth"
)

const (
	approverPairingDomain  = "racg/approver/pairing/v1"
	approverPollDomain     = "racg/approver/poll/v1"
	approverDecisionDomain = "racg/approver/decision/v1"

	approverChallengeTTL = 2 * time.Minute
	// Protocol safety bound for signed approver envelopes; transfer routes
	// keep unlimited bodies by product rule.
	approverMaxBodyBytes = 64 << 10
)

const (
	approverHeaderDevice    = "X-Racg-Approver-Device"
	approverHeaderChallenge = "X-Racg-Approver-Challenge"
	approverHeaderSignature = "X-Racg-Approver-Signature"
)

type approverPairingRequest struct {
	DeviceID    string `json:"device_id"`
	PublicKey   []byte `json:"public_key"`
	TokenSHA256 string `json:"token_sha256"`
	Challenge   string `json:"challenge"`
	Signature   []byte `json:"signature"`
}

type approverDecisionRequest struct {
	DeviceID        string `json:"device_id"`
	RequestID       string `json:"request_id"`
	Decision        string `json:"decision"`
	OperationSHA256 string `json:"operation_sha256"`
	Challenge       string `json:"challenge"`
	Signature       []byte `json:"signature"`
}

func (a *API) registerApproverRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/approver/challenge", a.handleApproverChallenge)
	mux.HandleFunc("/v1/approver/pairing", a.handleApproverPairing)
	mux.HandleFunc("/v1/approver/requests", a.handleApproverRequests)
	mux.HandleFunc("/v1/approver/requests/", a.handleApproverRequest)
	mux.HandleFunc("/v1/approver/decision", a.handleApproverDecision)
}

func (a *API) handleApproverChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	encoded := hex.EncodeToString(challenge)
	a.approverMu.Lock()
	a.approverChallenges[encoded] = time.Now().Add(approverChallengeTTL)
	now := time.Now()
	for key, expires := range a.approverChallenges {
		if now.After(expires) {
			delete(a.approverChallenges, key)
		}
	}
	a.approverMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"challenge": encoded})
}

// consumeApproverChallenge atomically validates and burns a challenge.
func (a *API) consumeApproverChallenge(challenge string) bool {
	a.approverMu.Lock()
	defer a.approverMu.Unlock()
	expires, ok := a.approverChallenges[challenge]
	if !ok || time.Now().After(expires) {
		delete(a.approverChallenges, challenge)
		return false
	}
	delete(a.approverChallenges, challenge)
	return true
}

func (a *API) handleApproverPairing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	var input approverPairingRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, approverMaxBodyBytes)).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid pairing request", "")
		return
	}
	deviceID, err := a.pairApproverDevice(input)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "PAIRING_FAILED", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device_id": deviceID})
}

func (a *API) pairApproverDevice(input approverPairingRequest) (string, error) {
	deviceID := strings.TrimSpace(input.DeviceID)
	if deviceID == "" || len(input.PublicKey) == 0 {
		return "", errors.New("device identity and public key required")
	}
	if a.st == nil {
		return "", errors.New("approver registry unavailable")
	}
	tokenBytes := a.approverTokenBytes()
	if len(tokenBytes) == 0 {
		return "", errors.New("approver pairing is disabled")
	}
	tokenHash := sha256.Sum256(tokenBytes)
	expectedTokenHex := hex.EncodeToString(tokenHash[:])
	if subtle.ConstantTimeCompare([]byte(expectedTokenHex), []byte(input.TokenSHA256)) != 1 {
		return "", errors.New("invalid pairing token")
	}
	if !a.consumeApproverChallenge(input.Challenge) {
		return "", errors.New("CHALLENGE_INVALID")
	}
	publicKeyHash := sha256.Sum256(input.PublicKey)
	message := approverMessage(approverPairingDomain, a.serverName,
		deviceID, hex.EncodeToString(publicKeyHash[:]), input.Challenge, expectedTokenHex)
	if err := verifyECDSAP256(input.PublicKey, message, input.Signature); err != nil {
		return "", err
	}
	if err := a.st.UpsertApproverDevice(context.Background(), deviceID, input.PublicKey, time.Now().UTC()); err != nil {
		return "", err
	}
	return deviceID, nil
}

// authenticateApproverPoll verifies the signed poll headers bound to the exact
// request path, then burns the challenge. Signature verification happens
// before challenge consumption so an unauthenticated caller cannot burn a
// challenge it has observed.
func (a *API) authenticateApproverPoll(r *http.Request) error {
	deviceID := strings.TrimSpace(r.Header.Get(approverHeaderDevice))
	challenge := strings.TrimSpace(r.Header.Get(approverHeaderChallenge))
	signature := strings.TrimSpace(r.Header.Get(approverHeaderSignature))
	if deviceID == "" || challenge == "" || signature == "" {
		return errors.New("missing approver credentials")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	publicKey, err := a.approverPublicKey(r.Context(), deviceID)
	if err != nil {
		return err
	}
	message := approverMessage(approverPollDomain, a.serverName, deviceID, r.URL.Path, challenge)
	if err := verifyECDSAP256(publicKey, message, sig); err != nil {
		return err
	}
	if !a.consumeApproverChallenge(challenge) {
		return errors.New("CHALLENGE_INVALID")
	}
	return nil
}

func (a *API) approverPublicKey(ctx context.Context, deviceID string) ([]byte, error) {
	if a.st == nil {
		return nil, errors.New("approver registry unavailable")
	}
	device, ok, err := a.st.GetApproverDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if !ok || !device.Enabled {
		return nil, errors.New("unknown or disabled approver device")
	}
	return device.PublicKey, nil
}

func (a *API) handleApproverRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if err := a.authenticateApproverPoll(r); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": a.PendingForApprover()})
}

func (a *API) handleApproverRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if err := a.authenticateApproverPoll(r); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), "")
		return
	}
	requestID := strings.TrimPrefix(r.URL.Path, "/v1/approver/requests/")
	request, ok := a.RequestForApprover(requestID)
	if !ok {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found or not pending", requestID)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

func (a *API) handleApproverDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	var input approverDecisionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, approverMaxBodyBytes)).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid decision", "")
		return
	}
	publicKey, err := a.approverPublicKey(r.Context(), strings.TrimSpace(input.DeviceID))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), input.RequestID)
		return
	}
	message := approverMessage(approverDecisionDomain, a.serverName,
		input.DeviceID, input.RequestID, input.OperationSHA256, input.Decision, input.Challenge)
	if err := verifyECDSAP256(publicKey, message, input.Signature); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), input.RequestID)
		return
	}
	if !a.consumeApproverChallenge(input.Challenge) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "CHALLENGE_INVALID", input.RequestID)
		return
	}
	// Bind the decision to the exact stored operation bytes: an approver can
	// only decide what it actually saw.
	request, ok := a.RequestForApprover(input.RequestID)
	if !ok {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found or not pending", input.RequestID)
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.OpSHA256), []byte(input.OperationSHA256)) != 1 {
		writeError(w, http.StatusBadRequest, "OPERATION_MISMATCH", "decision is bound to different operation bytes", input.RequestID)
		return
	}
	claims := auth.Claims{SessionID: "approver", ClientID: input.DeviceID}
	if err := a.decideForApprover(r.Context(), input.RequestID, input.Decision, claims); err != nil {
		status := http.StatusConflict
		switch err.Error() {
		case "REQUEST_NOT_FOUND":
			status = http.StatusNotFound
		case "REQUEST_NOT_PENDING", "BAD_REQUEST":
			status = http.StatusBadRequest
		}
		writeError(w, status, "DECISION_REJECTED", err.Error(), input.RequestID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device_id": input.DeviceID})
}

func (a *API) decideForApprover(ctx context.Context, requestID, decision string, claims auth.Claims) error {
	return a.decideInternalWithSource(ctx, requestID, decision, claims, nil, "approver:"+claims.ClientID)
}

func approverMessage(domain, serverID string, parts ...string) []byte {
	message := domain + "\x00" + serverID
	for _, part := range parts {
		message += "\x00" + part
	}
	return []byte(message)
}
