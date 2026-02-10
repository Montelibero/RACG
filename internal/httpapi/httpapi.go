package httpapi

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/events"
	"github.com/itolstov/racg/internal/executor"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/version"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

//go:embed openapi.json
var openapiFS embed.FS

type Option func(*API)

func WithPairing(p *auth.Pairing) Option {
	return func(a *API) { a.pairing = p }
}

func WithTokenManager(m *auth.TokenManager) Option {
	return func(a *API) { a.tokens = m }
}

func WithHub(h *events.Hub) Option {
	return func(a *API) { a.hub = h }
}

func WithRulesEngine(e *rules.Engine) Option {
	return func(a *API) { a.rules = e }
}

func WithExecutor(x *executor.Executor) Option {
	return func(a *API) { a.exec = x }
}

type API struct {
	cfg config.Config

	pairing *auth.Pairing
	tokens  *auth.TokenManager
	hub     *events.Hub
	rules   *rules.Engine
	exec    *executor.Executor
	sem     chan struct{}

	mu             sync.Mutex
	lockedClientIP string

	reqsMu sync.Mutex
	reqs   map[string]requestRecord
}

type requestRecord struct {
	ID     string          `json:"request_id"`
	Status string          `json:"status"`
	Op     json.RawMessage `json:"op"`

	Decision *decisionRecord `json:"decision,omitempty"`
	Result   *resultRecord   `json:"result,omitempty"`
}

type decisionRecord struct {
	Decision       string `json:"decision"`
	DecisionSource string `json:"decision_source"`
	DecidedAt      string `json:"decided_at"`
	RuleID         string `json:"rule_id,omitempty"`
}

type resultRecord struct {
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	DurationMs      int64  `json:"duration_ms"`
	ExitCode        int    `json:"exit_code"`
	Status          string `json:"status"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	StdoutSHA256    string `json:"stdout_sha256"`
	StderrSHA256    string `json:"stderr_sha256"`
}

func New(cfg config.Config, opts ...Option) *API {
	a := &API{cfg: cfg, reqs: map[string]requestRecord{}}

	a.pairing = auth.NewPairing(6, time.Duration(cfg.PairingCodeTTLSeconds)*time.Second, auth.RealClock{})
	a.tokens = auth.NewTokenManager(auth.RealClock{})
	a.hub = events.NewHub()
	a.rules = rules.NewEngine()
	a.exec = executor.New(executor.Options{
		MaxOutputBytes: cfg.MaxOutputBytes,
		KillGrace:      3 * time.Second,
	})
	a.sem = make(chan struct{}, cfg.MaxConcurrency)

	for _, o := range opts {
		o(a)
	}
	return a
}

func (a *API) PairingCode() string {
	return a.pairing.Code()
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/openapi.json", a.handleOpenAPI)
	mux.HandleFunc("/v1/info", a.handleInfo)
	mux.HandleFunc("/v1/session/open", a.handleSessionOpen)
	mux.HandleFunc("/v1/session/me", a.withAuth(a.handleSessionMe))
	mux.HandleFunc("/v1/requests", a.withAuth(a.handleRequests))
	mux.HandleFunc("/v1/requests/", a.withAuth(a.handleRequestByID))
	mux.HandleFunc("/v1/events", a.handleEventsWS)

	if !a.cfg.LockFirstClientAddr {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		a.mu.Lock()
		locked := a.lockedClientIP
		a.mu.Unlock()
		if locked != "" && locked != ip {
			writeError(w, http.StatusForbidden, "CLIENT_ADDR_LOCKED", "client address is locked", "")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *API) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	b, err := openapiFS.ReadFile("openapi.json")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (a *API) handleInfo(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"server_version": version.Version,
		"api_versions":   []string{"v1"},
		"ws_url":         "/v1/events",
		"openapi_url":    "/openapi.json",
		"privilege_mode": "root",
		"limits": map[string]any{
			"default_timeout_sec": a.cfg.DefaultTimeoutSec,
			"max_output_bytes":    a.cfg.MaxOutputBytes,
			"max_concurrency":     a.cfg.MaxConcurrency,
		},
		"features": map[string]any{
			"lock_first_client_addr": a.cfg.LockFirstClientAddr,
		},
		"supported_ops": []string{
			"cmd.run",
			"fs.read",
			"fs.patch_unified",
			"conf.set_kv",
			"svc.status",
			"svc.restart",
			"svc.logs",
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleSessionOpen(w http.ResponseWriter, r *http.Request) {
	if a.cfg.LockFirstClientAddr {
		ip := remoteIP(r)
		a.mu.Lock()
		if a.lockedClientIP == "" {
			// Lock on first successful pairing.
		} else if a.lockedClientIP != ip {
			a.mu.Unlock()
			writeError(w, http.StatusForbidden, "CLIENT_ADDR_LOCKED", "client address is locked", "")
			return
		}
		a.mu.Unlock()
	}

	var req struct {
		ClientID    string `json:"client_id"`
		PairingCode string `json:"pairing_code"`
	}
	if err := decodeJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error(), "")
		return
	}
	if strings.TrimSpace(req.ClientID) == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "client_id is required", "")
		return
	}

	if err := a.pairing.Consume(req.PairingCode); err != nil {
		code, status := mapPairingErr(err)
		writeError(w, status, code, code, "")
		return
	}

	if a.cfg.LockFirstClientAddr {
		ip := remoteIP(r)
		a.mu.Lock()
		if a.lockedClientIP == "" {
			a.lockedClientIP = ip
		}
		a.mu.Unlock()
	}

	sessionID := uuid.NewString()
	tok, exp := a.tokens.Issue(sessionID, req.ClientID, 8*time.Hour)

	resp := map[string]any{
		"session_id":    sessionID,
		"session_token": tok,
		"expires_at":    exp.Format(time.RFC3339Nano),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleSessionMe(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	resp := map[string]any{
		"session_id":     c.SessionID,
		"client_id":      c.ClientID,
		"expires_at":     c.ExpiresAt.Format(time.RFC3339Nano),
		"privilege_mode": "root",
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleRequests(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}

	var req struct {
		Op          rules.Op `json:"op"`
		ClientReqID string   `json:"client_req_id"`
	}
	if err := decodeJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error(), "")
		return
	}

	if strings.TrimSpace(req.Op.Type) == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "op.type is required", "")
		return
	}
	if len(req.Op.Payload) == 0 {
		req.Op.Payload = []byte(`{}`)
	}

	id := uuid.NewString()
	rec := requestRecord{ID: id, Status: "PENDING_APPROVAL", Op: mustJSON(req.Op)}
	respStatus := rec.Status

	a.reqsMu.Lock()
	a.reqs[id] = rec
	a.reqsMu.Unlock()

	a.hub.Publish(events.Event{
		Type:      "request.created",
		RequestID: id,
		SessionID: c.SessionID,
		ClientID:  c.ClientID,
		Data: map[string]any{
			"status": rec.Status,
		},
	})

	// Auto-approve via rules (MVP).
	if m, ok := a.rules.Match(c.SessionID, req.Op); ok {
		dec := &decisionRecord{
			Decision:       "ALLOW_RULE",
			DecisionSource: "rule",
			DecidedAt:      time.Now().UTC().Format(time.RFC3339Nano),
			RuleID:         m.RuleID,
		}
		a.reqsMu.Lock()
		rec2 := a.reqs[id]
		rec2.Status = "APPROVED"
		rec2.Decision = dec
		a.reqs[id] = rec2
		a.reqsMu.Unlock()

		respStatus = "APPROVED"
		a.hub.Publish(events.Event{
			Type:      "request.decision",
			RequestID: id,
			SessionID: c.SessionID,
			ClientID:  c.ClientID,
			Data: map[string]any{
				"decision":        dec.Decision,
				"decision_source": dec.DecisionSource,
				"rule_id":         m.RuleID,
				"status":          "APPROVED",
			},
		})
		// Execute asynchronously.
		go a.executeApprovedRequest(id, c, req.Op)
	}

	resp := map[string]any{"request_id": id, "status": respStatus}
	writeJSON(w, http.StatusOK, resp)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (a *API) executeApprovedRequest(requestID string, c auth.Claims, op rules.Op) {
	// Bounded concurrency.
	a.sem <- struct{}{}
	defer func() { <-a.sem }()

	// Mark RUNNING.
	startedAt := time.Now().UTC()
	a.reqsMu.Lock()
	rec, ok := a.reqs[requestID]
	if ok {
		rec.Status = "RUNNING"
		a.reqs[requestID] = rec
	}
	a.reqsMu.Unlock()

	a.hub.Publish(events.Event{
		Type:      "request.started",
		RequestID: requestID,
		SessionID: c.SessionID,
		ClientID:  c.ClientID,
		Data: map[string]any{
			"status": "RUNNING",
		},
	})

	var rr *resultRecord
	switch op.Type {
	case "cmd.run":
		var payload struct {
			Argv       []string `json:"argv"`
			Cwd        string   `json:"cwd"`
			TimeoutSec int      `json:"timeout_sec"`
		}
		_ = json.Unmarshal(op.Payload, &payload)
		timeout := time.Duration(payload.TimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = time.Duration(a.cfg.DefaultTimeoutSec) * time.Second
		}
		res := a.exec.Run(context.Background(), executor.Spec{
			Argv:    payload.Argv,
			Cwd:     payload.Cwd,
			Timeout: timeout,
		})
		finishedAt := time.Now().UTC()
		rr = &resultRecord{
			StartedAt:       startedAt.Format(time.RFC3339Nano),
			FinishedAt:      finishedAt.Format(time.RFC3339Nano),
			DurationMs:      res.DurationMs,
			ExitCode:        res.ExitCode,
			Status:          res.Status,
			Stdout:          res.Stdout,
			Stderr:          res.Stderr,
			StdoutTruncated: res.StdoutTruncated,
			StderrTruncated: res.StderrTruncated,
			StdoutSHA256:    res.StdoutSHA256,
			StderrSHA256:    res.StderrSHA256,
		}
	default:
		finishedAt := time.Now().UTC()
		rr = &resultRecord{
			StartedAt:  startedAt.Format(time.RFC3339Nano),
			FinishedAt: finishedAt.Format(time.RFC3339Nano),
			DurationMs: finishedAt.Sub(startedAt).Milliseconds(),
			ExitCode:   -1,
			Status:     "FAILED",
			Stderr:     "OP_NOT_SUPPORTED",
		}
	}

	terminalStatus := rr.Status
	switch rr.Status {
	case "SUCCEEDED", "FAILED", "TIMED_OUT":
		// ok
	default:
		terminalStatus = "FAILED"
	}

	a.reqsMu.Lock()
	rec2, ok := a.reqs[requestID]
	if ok {
		rec2.Result = rr
		rec2.Status = terminalStatus
		a.reqs[requestID] = rec2
	}
	a.reqsMu.Unlock()

	a.hub.Publish(events.Event{
		Type:      "request.finished",
		RequestID: requestID,
		SessionID: c.SessionID,
		ClientID:  c.ClientID,
		Data: map[string]any{
			"status":    terminalStatus,
			"exit_code": rr.ExitCode,
		},
	})
}

func (a *API) handleEventsWS(w http.ResponseWriter, r *http.Request) {
	_, ok := a.mustAuth(w, r)
	if !ok {
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// MVP: we do not use Origin checks because deployments vary (ssh tunnels, tailscale).
		// If exposed publicly, rely on token + optional IP-lock.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx := r.Context()
	ch, cancel := a.hub.Subscribe(64)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if err := wsjson.Write(ctx, conn, e); err != nil {
				return
			}
		}
	}
}

func (a *API) handleRequestByID(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/requests/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found", "")
		return
	}

	a.reqsMu.Lock()
	rec, ok := a.reqs[id]
	a.reqsMu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found", id)
		return
	}

	// In MVP we don't filter by session/client; token possession is sufficient.
	writeJSON(w, http.StatusOK, rec)
}

type authHandler func(http.ResponseWriter, *http.Request, auth.Claims)

func (a *API) withAuth(next authHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := a.mustAuth(w, r)
		if !ok {
			return
		}
		next(w, r, claims)
	}
}

func (a *API) mustAuth(w http.ResponseWriter, r *http.Request) (auth.Claims, bool) {
	tok := bearerToken(r.Header.Get("Authorization"))
	if tok == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing bearer token", "")
		return auth.Claims{}, false
	}
	claims, err := a.tokens.Verify(tok)
	if err != nil {
		code, status := mapAuthErr(err)
		writeError(w, status, code, code, "")
		return auth.Claims{}, false
	}
	return claims, true
}

func mapPairingErr(err error) (code string, status int) {
	switch {
	case errors.Is(err, auth.ErrPairingCodeInvalid):
		return "PAIRING_CODE_INVALID", http.StatusForbidden
	case errors.Is(err, auth.ErrPairingCodeExpired):
		return "PAIRING_CODE_EXPIRED", http.StatusForbidden
	case errors.Is(err, auth.ErrPairingCodeUsed):
		return "PAIRING_CODE_USED", http.StatusForbidden
	default:
		return "FORBIDDEN", http.StatusForbidden
	}
}

func mapAuthErr(err error) (code string, status int) {
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		return "UNAUTHORIZED", http.StatusUnauthorized
	case errors.Is(err, auth.ErrSessionExpired):
		return "SESSION_EXPIRED", http.StatusUnauthorized
	default:
		return "UNAUTHORIZED", http.StatusUnauthorized
	}
}

func bearerToken(v string) string {
	v = strings.TrimSpace(v)
	const p = "Bearer "
	if len(v) < len(p) {
		return ""
	}
	// constant-time prefix compare.
	if subtle.ConstantTimeCompare([]byte(v[:len(p)]), []byte(p)) != 1 {
		return ""
	}
	return strings.TrimSpace(v[len(p):])
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func decodeJSON(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, msg, requestID string) {
	writeJSON(w, status, errorEnvelope{Error: errorBody{Code: code, Message: msg, RequestID: requestID}})
}
