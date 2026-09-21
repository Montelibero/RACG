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
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/rules"
)

const (
	approverPairingDomain  = "racg/approver/pairing/v1"
	approverPollDomain     = "racg/approver/poll/v1"
	approverDecisionDomain = "racg/approver/decision/v1"
	approverAdminDomain    = "racg/approver/admin/v1"

	approverChallengeTTL = 2 * time.Minute
	// Protocol safety bound for signed approver envelopes; transfer routes
	// keep unlimited bodies by product rule.
	approverMaxBodyBytes = 64 << 10
	// Enrollment tokens (8.2) are single-use and die young: a forgotten QR
	// screenshot must become worthless on its own.
	approverPairingTokenTTL = 10 * time.Minute
)

const (
	approverHeaderDevice    = "X-Racg-Approver-Device"
	approverHeaderChallenge = "X-Racg-Approver-Challenge"
	approverHeaderSignature = "X-Racg-Approver-Signature"
)

type approverPairingRequest struct {
	DeviceID      string `json:"device_id"`
	PublicKey     []byte `json:"public_key"`
	PollPublicKey []byte `json:"poll_public_key,omitempty"`
	TokenSHA256   string `json:"token_sha256"`
	Challenge     string `json:"challenge"`
	Signature     []byte `json:"signature"`
}

// approverAdminRequest is a device-signed administrative mutation issued from
// the phone (extend/revoke a session or device, mint a pairing code).
type approverAdminRequest struct {
	DeviceID  string `json:"device_id"`
	Action    string `json:"action"`
	TargetID  string `json:"target_id"`
	Challenge string `json:"challenge"`
	Signature []byte `json:"signature"`
}

type approverDecisionRequest struct {
	DeviceID        string `json:"device_id"`
	RequestID       string `json:"request_id"`
	Decision        string `json:"decision"`
	OperationSHA256 string `json:"operation_sha256"`
	Challenge       string `json:"challenge"`
	Signature       []byte `json:"signature"`
	// Reusable-grant extension (item 13): when RuleDuration is set the
	// decision creates session- or always-scoped rules from RulePatterns —
	// one rule per checked scope line, exactly like the TUI form.
	// Duration: "1h", "24h" (session rules with TTL), "session", "always".
	RulePatterns []string `json:"rule_patterns"`
	RuleDuration string   `json:"rule_duration,omitempty"`
}

func (a *API) registerApproverRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/approver/challenge", a.handleApproverChallenge)
	mux.HandleFunc("/v1/approver/pairing", a.handleApproverPairing)
	mux.HandleFunc("/v1/approver/requests", a.handleApproverRequests)
	mux.HandleFunc("/v1/approver/requests/", a.handleApproverRequest)
	mux.HandleFunc("/v1/approver/history", a.handleApproverHistory)
	mux.HandleFunc("/v1/approver/decision", a.handleApproverDecision)
	mux.HandleFunc("/v1/approver/sessions", a.handleApproverSessions)
	mux.HandleFunc("/v1/approver/sessions/extend", a.handleApproverSessionExtend)
	mux.HandleFunc("/v1/approver/sessions/revoke", a.handleApproverSessionRevoke)
	mux.HandleFunc("/v1/approver/devices", a.handleApproverDevices)
	mux.HandleFunc("/v1/approver/devices/revoke", a.handleApproverDeviceRevoke)
	mux.HandleFunc("/v1/approver/pairing-code", a.handleApproverPairingCode)
	mux.HandleFunc("/v1/approver/enrollment", a.handleApproverEnrollment)
	mux.HandleFunc("/v1/approver/request/kill", a.handleApproverRequestKill)
	mux.HandleFunc("/v1/approver/events", a.handleApproverEvents)
	mux.HandleFunc("/v1/admin/approver/enrollment", a.handleAdminApproverEnrollment)
	mux.HandleFunc("/v1/admin/pairing-code", a.handleAdminPairingCode)
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
	expectedTokenHex, ok := a.validApproverToken(input.TokenSHA256)
	if !ok {
		return "", errors.New("invalid pairing token")
	}
	if !a.consumeApproverChallenge(input.Challenge) {
		return "", errors.New("CHALLENGE_INVALID")
	}
	publicKeyHash := sha256.Sum256(input.PublicKey)
	pollKeyHex := ""
	if len(input.PollPublicKey) > 0 {
		pollHash := sha256.Sum256(input.PollPublicKey)
		pollKeyHex = hex.EncodeToString(pollHash[:])
	}
	message := approverMessage(approverPairingDomain, a.serverName,
		deviceID, hex.EncodeToString(publicKeyHash[:]), pollKeyHex, input.Challenge, expectedTokenHex)
	if err := verifyECDSAP256(input.PublicKey, message, input.Signature); err != nil {
		return "", err
	}
	if err := a.st.UpsertApproverDevice(context.Background(), deviceID, input.PublicKey, input.PollPublicKey, time.Now().UTC()); err != nil {
		return "", err
	}
	// The enrollment token is single-use: burn it so the same QR can never
	// pair a second device.
	a.approverMu.Lock()
	a.approverPairingToken = nil
	a.approverPairingTokenExpires = time.Time{}
	a.approverMu.Unlock()
	return deviceID, nil
}

// authenticateApproverPoll verifies the signed poll headers bound to the exact
// request path, then burns the challenge. Signature verification happens
// before challenge consumption so an unauthenticated caller cannot burn a
// challenge it has observed. Devices enrolled with a dedicated poll key
// (9.6) must sign reads with it; legacy single-key devices keep polling with
// their approval key.
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
	device, err := a.approverDevice(r.Context(), deviceID)
	if err != nil {
		return err
	}
	pollKey := device.PollPublicKey
	if len(pollKey) == 0 {
		pollKey = device.PublicKey
	}
	message := approverMessage(approverPollDomain, a.serverName, deviceID, r.URL.Path, challenge)
	if err := verifyECDSAP256(pollKey, message, sig); err != nil {
		return err
	}
	if !a.consumeApproverChallenge(challenge) {
		return errors.New("CHALLENGE_INVALID")
	}
	return nil
}

// authenticateApproverAdmin verifies a device-signed administrative mutation
// (approval key only — decisions and management stay biometry-bound) and
// burns the challenge.
func (a *API) authenticateApproverAdmin(body []byte) (approverAdminRequest, error) {
	var input approverAdminRequest
	if err := json.Unmarshal(body, &input); err != nil {
		return input, errors.New("invalid request")
	}
	if strings.TrimSpace(input.DeviceID) == "" || strings.TrimSpace(input.Action) == "" {
		return input, errors.New("device identity and action required")
	}
	sig := input.Signature // json.Unmarshal already base64-decoded the field
	device, err := a.approverDevice(context.Background(), strings.TrimSpace(input.DeviceID))
	if err != nil {
		return input, err
	}
	message := approverMessage(approverAdminDomain, a.serverName,
		input.DeviceID, input.Action, input.TargetID, input.Challenge)
	if err := verifyECDSAP256(device.PublicKey, message, sig); err != nil {
		return input, err
	}
	if !a.consumeApproverChallenge(input.Challenge) {
		return input, errors.New("CHALLENGE_INVALID")
	}
	return input, nil
}

func (a *API) approverDevice(ctx context.Context, deviceID string) (ApproverDeviceView, error) {
	if a.st == nil {
		return ApproverDeviceView{}, errors.New("approver registry unavailable")
	}
	device, ok, err := a.st.GetApproverDevice(ctx, deviceID)
	if err != nil {
		return ApproverDeviceView{}, err
	}
	if !ok || !device.Enabled {
		return ApproverDeviceView{}, errors.New("unknown or disabled approver device")
	}
	return ApproverDeviceView{PublicKey: device.PublicKey, PollPublicKey: device.PollPublicKey}, nil
}

// ApproverDeviceView is the httpapi-facing subset of a stored approver device.
type ApproverDeviceView struct {
	PublicKey     []byte
	PollPublicKey []byte
}

func (a *API) approverPublicKey(ctx context.Context, deviceID string) ([]byte, error) {
	device, err := a.approverDevice(ctx, deviceID)
	if err != nil {
		return nil, err
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
	// Item 13: scope candidates for the timed-grant dialog.
	if strings.HasSuffix(requestID, "/scope") {
		requestID = strings.TrimSuffix(requestID, "/scope")
		if requestID == "" {
			writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found or not pending", requestID)
			return
		}
		a.writeApproverScopeCandidates(w, requestID)
		return
	}
	request, ok := a.RequestForApprover(requestID)
	if !ok {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found or not pending", requestID)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

// writeApproverScopeCandidates returns the TUI-compatible reusable-scope
// candidates for a pending request (segments of a shell script, paths for
// fs.*/conf.* ops). Authentication already happened in
// handleApproverRequest — burning the challenge again here would fail.
func (a *API) writeApproverScopeCandidates(w http.ResponseWriter, requestID string) {
	candidates := a.RuleScopeCandidatesForTUI(requestID)
	if len(candidates) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"candidates": []map[string]any{}, "problem": "no reusable rule scope could be derived"})
		return
	}
	out := make([]map[string]any, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, map[string]any{"op_type": c.OpType, "segment": c.Segment, "pattern": c.Pattern})
	}
	writeJSON(w, http.StatusOK, map[string]any{"candidates": out})
}

// handleApproverHistory returns recent decisions from every source (phone,
// TUI, auto-rules) — the phone history screen (item 16).
func (a *API) handleApproverHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if err := a.authenticateApproverPoll(r); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), "")
		return
	}
	if a.st == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "approver registry unavailable", "")
		return
	}
	rows, err := a.st.ListRecentDecisions(r.Context(), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		entry := map[string]any{
			"request_id":      row.RequestID,
			"decision":        row.Decision,
			"decision_source": row.DecisionSource,
			"decided_at":      row.DecidedAt.UTC().Format(time.RFC3339Nano),
		}
		if row.RuleID != "" {
			entry["rule_id"] = row.RuleID
		}
		if row.ClientID != "" {
			entry["client_id"] = row.ClientID
		}
		if row.Status != "" {
			entry["status"] = row.Status
		}
		if len(row.OpJSON) > 0 {
			entry["op"] = json.RawMessage(row.OpJSON)
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": out})
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
	// Item 6/3: session-scoped grants must bind to the TARGET agent session,
	// resolved server-side; the phone never sees session IDs in its list.
	claims, err := a.approverDecisionClaims(input.RequestID, input.DeviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", err.Error(), input.RequestID)
		return
	}
	source := "approver:" + input.DeviceID
	if input.RuleDuration != "" {
		// Scoped reusable grant (item 13): one rule per checked scope line,
		// built exactly like the TUI form does.
		patterns := make([]string, 0, len(input.RulePatterns))
		for _, p := range input.RulePatterns {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				patterns = append(patterns, trimmed)
			}
		}
		if len(patterns) == 0 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "at least one rule pattern required for reusable grants", input.RequestID)
			return
		}
		var op rules.Op
		_ = json.Unmarshal(request.Op, &op)
		rulesToCreate := make([]rules.Rule, 0, len(patterns))
		for _, pattern := range patterns {
			rule, err := ruleFromScopePatternForOp(op, pattern)
			if err != nil {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error(), input.RequestID)
				return
			}
			rulesToCreate = append(rulesToCreate, rule)
		}
		decision := input.Decision
		switch input.RuleDuration {
		case "1h", "24h":
			// TTL grants live inside the agent session: when the session is
			// revoked the rule dies with it, regardless of the TTL.
			decision = "ALLOW_SESSION"
			expires := time.Now().UTC().Add(1 * time.Hour)
			if input.RuleDuration == "24h" {
				expires = expires.Add(23 * time.Hour)
			}
			for i := range rulesToCreate {
				rulesToCreate[i].ExpiresAt = &expires
			}
		case "session":
			decision = "ALLOW_SESSION"
		case "always":
			decision = "ALLOW_ALWAYS"
		default:
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown rule duration", input.RequestID)
			return
		}
		if err := a.decideInternalWithSource(r.Context(), input.RequestID, decision, claims, rulesToCreate, source); err != nil {
			writeDecisionError(w, err, input.RequestID)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device_id": input.DeviceID, "rules": len(rulesToCreate)})
		return
	}
	if err := a.decideInternalWithSource(r.Context(), input.RequestID, input.Decision, claims, nil, source); err != nil {
		writeDecisionError(w, err, input.RequestID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device_id": input.DeviceID})
}

func writeDecisionError(w http.ResponseWriter, err error, requestID string) {
	status := http.StatusConflict
	switch err.Error() {
	case "REQUEST_NOT_FOUND":
		status = http.StatusNotFound
	case "REQUEST_NOT_PENDING", "BAD_REQUEST":
		status = http.StatusBadRequest
	}
	writeError(w, status, "DECISION_REJECTED", err.Error(), requestID)
}

func (a *API) decideForApprover(ctx context.Context, requestID, decision string, claims auth.Claims) error {
	return a.decideInternalWithSource(ctx, requestID, decision, claims, nil, "approver:"+claims.ClientID)
}

// approverDecisionClaims resolves the decision principal for a pending
// request: the approver device acts on behalf of the request's agent session,
// which stays hidden from the phone (ApproverRequest carries no SessionID).
func (a *API) approverDecisionClaims(requestID, deviceID string) (auth.Claims, error) {
	a.reqsMu.Lock()
	defer a.reqsMu.Unlock()
	rec, ok := a.reqs[requestID]
	if !ok {
		return auth.Claims{}, errors.New("REQUEST_NOT_FOUND")
	}
	return auth.Claims{SessionID: rec.SessionID, ClientID: deviceID}, nil
}

func approverMessage(domain, serverID string, parts ...string) []byte {
	message := domain + "\x00" + serverID
	for _, part := range parts {
		message += "\x00" + part
	}
	return []byte(message)
}

// sessionTTL returns the configured auth-token lifetime; 0 means no expiry.
func (a *API) sessionTTL() time.Duration {
	if a.cfg.SessionTTLHours <= 0 {
		return 0
	}
	return time.Duration(a.cfg.SessionTTLHours) * time.Hour
}

// ---- Phone-side session/device management (items 6, 8.3, 8.4) ----

func (a *API) handleApproverSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if err := a.authenticateApproverPoll(r); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), "")
		return
	}
	sessions := []map[string]any{}
	for _, s := range a.tokens.ListSessions() {
		entry := map[string]any{"session_id": s.SessionID, "client_id": s.ClientID}
		if !s.ExpiresAt.IsZero() {
			entry["expires_at"] = s.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		sessions = append(sessions, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (a *API) handleApproverSessionExtend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, approverMaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request", "")
		return
	}
	input, err := a.authenticateApproverAdmin(body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), input.TargetID)
		return
	}
	expires, err := a.tokens.ExtendSession(input.TargetID, a.sessionTTL())
	if err != nil {
		writeError(w, http.StatusNotFound, "SESSION_NOT_FOUND", err.Error(), input.TargetID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session_id": input.TargetID, "expires_at": expires.UTC().Format(time.RFC3339Nano)})
}

func (a *API) handleApproverSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, approverMaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request", "")
		return
	}
	input, err := a.authenticateApproverAdmin(body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), input.TargetID)
		return
	}
	revoked := a.tokens.RevokeSession(input.TargetID)
	if a.st != nil {
		_ = a.st.EndSession(r.Context(), input.TargetID, time.Now().UTC())
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session_id": input.TargetID, "revoked": revoked})
}

func (a *API) handleApproverDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if err := a.authenticateApproverPoll(r); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), "")
		return
	}
	if a.st == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "approver registry unavailable", "")
		return
	}
	devices, err := a.st.ListApproverDevices(r.Context(), 1000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	out := []map[string]any{}
	for _, d := range devices {
		out = append(out, map[string]any{
			"device_id":    d.DeviceID,
			"created_at":   d.CreatedAt.UTC().Format(time.RFC3339Nano),
			"enabled":      d.Enabled,
			"has_poll_key": len(d.PollPublicKey) > 0,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (a *API) handleApproverDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, approverMaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request", "")
		return
	}
	input, err := a.authenticateApproverAdmin(body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), input.TargetID)
		return
	}
	if a.st == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "approver registry unavailable", input.TargetID)
		return
	}
	if err := a.st.SetApproverDeviceEnabled(r.Context(), input.TargetID, false, time.Now().UTC()); err != nil {
		writeError(w, http.StatusNotFound, "DEVICE_NOT_FOUND", err.Error(), input.TargetID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device_id": input.TargetID})
}

func (a *API) handleApproverPairingCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, approverMaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request", "")
		return
	}
	if _, err := a.authenticateApproverAdmin(body); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), "")
		return
	}
	a.pairing.Regenerate()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"pairing_code":       a.pairing.Code(),
		"expires_in_seconds": int(a.pairing.ExpiresIn().Seconds()),
	})
}

// handleApproverEnrollment mints a fresh one-time approver enrollment token
// for an already-enrolled device ("transfer to a new phone"): the old phone
// signs the admin action and renders a standard setup QR, the new phone
// pairs through the regular /v1/approver/pairing flow. The minted token is
// single-use, expires after approverPairingTokenTTL, and invalidates any
// previously issued enrollment token.
func (a *API) handleApproverEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, approverMaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request", "")
		return
	}
	input, err := a.authenticateApproverAdmin(body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), input.TargetID)
		return
	}
	if input.Action != "enrollment" {
		writeError(w, http.StatusBadRequest, "BAD_ACTION", "expected action enrollment", input.TargetID)
		return
	}
	token, expires, err := a.MintApproverPairingToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token_b64": token, "expires_at": expires.Format(time.RFC3339Nano)})
}

// handleApproverRequestKill stops a running (or still queued) request from
// the phone: a device-signed admin action with target_id = request_id.
// The phone sees request owners in its history, so it can kill a wrong
// command regardless of which agent session submitted it. Terminal-status
// requests are reported as already finished instead of being mutated.
func (a *API) handleApproverRequestKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, approverMaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request", "")
		return
	}
	input, err := a.authenticateApproverAdmin(body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), input.TargetID)
		return
	}
	if input.Action != "request.kill" {
		writeError(w, http.StatusBadRequest, "BAD_ACTION", "expected action request.kill", input.TargetID)
		return
	}
	requestID := strings.TrimSpace(input.TargetID)
	if requestID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "target_id (request_id) required", "")
		return
	}
	a.reqsMu.Lock()
	rec, ok := a.reqs[requestID]
	a.reqsMu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found", requestID)
		return
	}
	if terminalRequestStatus(rec.Status) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": requestID, "status": rec.Status, "already_finished": true})
		return
	}
	// Attribute the kill to the request owner so hub events and audit
	// reflect the affected session, not the phone.
	if err := a.killInternal(context.Background(), requestID, auth.Claims{SessionID: rec.SessionID, ClientID: rec.ClientID}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), requestID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": requestID, "killed": true})
}

func terminalRequestStatus(status string) bool {
	switch status {
	case "SUCCEEDED", "FAILED", "TIMED_OUT", "KILLED", "DENIED", "CANCELED":
		return true
	default:
		return false
	}
}

// ---- Privileged admin endpoints (pipeline unix socket only) ----

// adminAuthorized allows requests that arrived over a local unix socket
// (no TCP host:port in RemoteAddr). The facade proxies these over the
// permission-restricted pipeline socket; network callers can never reach them.
func adminAuthorized(r *http.Request) bool {
	_, _, err := net.SplitHostPort(r.RemoteAddr)
	return err != nil
}

func (a *API) handleAdminApproverEnrollment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if !adminAuthorized(r) {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "admin endpoints are unix-socket only", "")
		return
	}
	token, expires, err := a.MintApproverPairingToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approver_token_b64": token, "expires_at": expires.Format(time.RFC3339Nano)})
}

func (a *API) handleAdminPairingCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if !adminAuthorized(r) {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "admin endpoints are unix-socket only", "")
		return
	}
	a.pairing.Regenerate()
	writeJSON(w, http.StatusOK, map[string]any{
		"pairing_code":       a.pairing.Code(),
		"expires_in_seconds": int(a.pairing.ExpiresIn().Seconds()),
	})
}
