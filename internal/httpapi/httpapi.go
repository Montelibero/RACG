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
	"github.com/itolstov/racg/internal/store"
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

func WithExecutor(x CmdRunner) Option {
	return func(a *API) { a.exec = x }
}

func WithStore(s *store.Store) Option {
	return func(a *API) { a.st = s }
}

type CmdRunner interface {
	Run(ctx context.Context, s executor.Spec) executor.Result
}

type API struct {
	cfg config.Config

	pairing *auth.Pairing
	tokens  *auth.TokenManager
	hub     *events.Hub
	rules   *rules.Engine
	exec    CmdRunner
	st      *store.Store
	sem     chan struct{}

	mu             sync.Mutex
	lockedClientIP string

	reqsMu sync.Mutex
	reqs   map[string]requestRecord

	runningMu sync.Mutex
	running   map[string]context.CancelFunc
}

type requestRecord struct {
	ID     string          `json:"request_id"`
	Status string          `json:"status"`
	Op     json.RawMessage `json:"op"`

	Decision *decisionRecord `json:"decision,omitempty"`
	Result   *resultRecord   `json:"result,omitempty"`

	RiskFlags []string `json:"risk_flags,omitempty"`

	SessionID string `json:"session_id,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// TUIRequest is a summarized view used by the built-in TUI.
type TUIRequest struct {
	ID        string
	Summary   string
	SessionID string
	ClientID  string
	RiskFlags []string
	CreatedAt string
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
	a := &API{cfg: cfg, reqs: map[string]requestRecord{}, running: map[string]context.CancelFunc{}}

	a.pairing = auth.NewPairing(6, time.Duration(cfg.PairingCodeTTLSeconds)*time.Second, auth.RealClock{})
	a.tokens = auth.NewTokenManager(auth.RealClock{})
	a.hub = events.NewHub()
	a.rules = rules.NewEngine()
	a.exec = executor.New(executor.Options{
		MaxOutputBytes: cfg.MaxOutputBytes,
		KillGrace:      time.Duration(cfg.KillGraceSec) * time.Second,
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

// ListPendingForTUI returns pending requests for display/approval.
func (a *API) ListPendingForTUI() []TUIRequest {
	a.reqsMu.Lock()
	defer a.reqsMu.Unlock()
	out := make([]TUIRequest, 0, 64)
	for _, rec := range a.reqs {
		if rec.Status != "PENDING_APPROVAL" {
			continue
		}
		out = append(out, TUIRequest{
			ID:        rec.ID,
			Summary:   summarizeOp(rec),
			SessionID: rec.SessionID,
			ClientID:  rec.ClientID,
			RiskFlags: append([]string(nil), rec.RiskFlags...),
			CreatedAt: rec.CreatedAt,
		})
	}
	return out
}

// DecideForTUI applies a decision without HTTP auth (used by in-process TUI).
func (a *API) DecideForTUI(requestID string, decision string) error {
	a.reqsMu.Lock()
	rec, ok := a.reqs[requestID]
	a.reqsMu.Unlock()
	if !ok {
		return errors.New("REQUEST_NOT_FOUND")
	}
	claims := auth.Claims{SessionID: rec.SessionID, ClientID: rec.ClientID}
	return a.decideInternal(requestID, decision, claims)
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

	startedAt := time.Now().UTC()
	sessionID := uuid.NewString()
	if a.st != nil {
		if err := a.st.InsertSession(r.Context(), store.Session{ID: sessionID, StartedAt: startedAt}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
			return
		}
	}
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
	switch r.Method {
	case http.MethodPost:
		// continue
	case http.MethodGet:
		a.handleRequestsList(w, r, c)
		return
	default:
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
	rec := requestRecord{
		ID:        id,
		Status:    "PENDING_APPROVAL",
		Op:        mustJSON(req.Op),
		RiskFlags: riskFlags(req.Op),
		SessionID: c.SessionID,
		ClientID:  c.ClientID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
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

func (a *API) handleRequestsList(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status == "" {
		status = "PENDING_APPROVAL"
	}
	limit := 100

	a.reqsMu.Lock()
	defer a.reqsMu.Unlock()
	var out []requestRecord
	for _, rec := range a.reqs {
		if rec.Status == status {
			out = append(out, rec)
			if len(out) >= limit {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (a *API) executeApprovedRequest(requestID string, c auth.Claims, op rules.Op) {
	a.reqsMu.Lock()
	rec0, ok0 := a.reqs[requestID]
	a.reqsMu.Unlock()
	if ok0 && rec0.Status == "KILLED" {
		return
	}

	// Bounded concurrency.
	a.sem <- struct{}{}
	defer func() { <-a.sem }()

	a.reqsMu.Lock()
	rec0, ok0 = a.reqs[requestID]
	a.reqsMu.Unlock()
	if ok0 && rec0.Status == "KILLED" {
		return
	}

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

		execCtx, cancel := context.WithCancel(context.Background())
		a.runningMu.Lock()
		a.running[requestID] = cancel
		a.runningMu.Unlock()

		res := a.exec.Run(execCtx, executor.Spec{
			Argv:    payload.Argv,
			Cwd:     payload.Cwd,
			Timeout: timeout,
		})
		a.runningMu.Lock()
		delete(a.running, requestID)
		a.runningMu.Unlock()

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
	case "KILLED":
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

func (a *API) handleDecision(w http.ResponseWriter, r *http.Request, c auth.Claims, requestID string) {
	var req struct {
		Decision string `json:"decision"`
	}
	if err := decodeJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error(), requestID)
		return
	}

	if err := a.decideInternal(requestID, req.Decision, c); err != nil {
		switch err.Error() {
		case "REQUEST_NOT_FOUND":
			writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found", requestID)
		case "REQUEST_NOT_PENDING":
			writeError(w, http.StatusConflict, "REQUEST_NOT_PENDING", "request is not pending approval", requestID)
		case "ALLOW_ALWAYS_NOT_PERMITTED":
			writeError(w, http.StatusForbidden, "ALLOW_ALWAYS_NOT_PERMITTED", "allow always not permitted for dangerous requests", requestID)
		case "BAD_REQUEST":
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "bad request", requestID)
		default:
			writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), requestID)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) decideInternal(requestID string, decision string, c auth.Claims) error {
	decision = strings.TrimSpace(decision)
	if decision == "" {
		return errors.New("BAD_REQUEST")
	}

	a.reqsMu.Lock()
	rec, ok := a.reqs[requestID]
	if !ok {
		a.reqsMu.Unlock()
		return errors.New("REQUEST_NOT_FOUND")
	}
	if rec.Status != "PENDING_APPROVAL" {
		a.reqsMu.Unlock()
		return errors.New("REQUEST_NOT_PENDING")
	}

	var op rules.Op
	_ = json.Unmarshal(rec.Op, &op)
	dangerous := isDangerous(rec.RiskFlags)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	dec := &decisionRecord{
		Decision:       decision,
		DecisionSource: "tui",
		DecidedAt:      now,
	}

	switch decision {
	case "DENY":
		rec.Status = "DENIED"
		rec.Decision = dec
		a.reqs[requestID] = rec
		a.reqsMu.Unlock()

		a.hub.Publish(events.Event{
			Type:      "request.decision",
			RequestID: requestID,
			SessionID: c.SessionID,
			ClientID:  c.ClientID,
			Data: map[string]any{
				"decision":        "DENY",
				"decision_source": "tui",
				"status":          "DENIED",
			},
		})
		return nil

	case "ALLOW_ONCE", "ALLOW_SESSION", "ALLOW_ALWAYS":
		if decision == "ALLOW_ALWAYS" && dangerous && !a.cfg.AllowAlwaysForDangerous {
			a.reqsMu.Unlock()
			return errors.New("ALLOW_ALWAYS_NOT_PERMITTED")
		}

		rec.Status = "APPROVED"
		rec.Decision = dec
		a.reqs[requestID] = rec
		a.reqsMu.Unlock()

		if decision == "ALLOW_SESSION" || decision == "ALLOW_ALWAYS" {
			ruleID := uuid.NewString()
			r, ok := ruleFromOpExact(ruleID, op)
			if ok {
				if decision == "ALLOW_SESSION" {
					a.rules.AddSession(c.SessionID, r)
				} else {
					a.rules.AddAlways(r)
				}
			}
		}

		a.hub.Publish(events.Event{
			Type:      "request.decision",
			RequestID: requestID,
			SessionID: c.SessionID,
			ClientID:  c.ClientID,
			Data: map[string]any{
				"decision":        decision,
				"decision_source": "tui",
				"status":          "APPROVED",
			},
		})

		go a.executeApprovedRequest(requestID, c, op)
		return nil
	default:
		a.reqsMu.Unlock()
		return errors.New("BAD_REQUEST")
	}
}

func (a *API) handleKill(w http.ResponseWriter, r *http.Request, c auth.Claims, requestID string) {
	a.reqsMu.Lock()
	rec, ok := a.reqs[requestID]
	a.reqsMu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found", requestID)
		return
	}

	// If not running yet, mark killed and do not execute.
	if rec.Status == "APPROVED" {
		a.reqsMu.Lock()
		rec2 := a.reqs[requestID]
		rec2.Status = "KILLED"
		rec2.Result = &resultRecord{
			StartedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			FinishedAt: time.Now().UTC().Format(time.RFC3339Nano),
			DurationMs: 0,
			ExitCode:   -1,
			Status:     "KILLED",
			Stderr:     "killed before start",
		}
		a.reqs[requestID] = rec2
		a.reqsMu.Unlock()

		a.hub.Publish(events.Event{
			Type:      "request.finished",
			RequestID: requestID,
			SessionID: c.SessionID,
			ClientID:  c.ClientID,
			Data: map[string]any{
				"status": "KILLED",
			},
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	a.runningMu.Lock()
	cancel, okCancel := a.running[requestID]
	a.runningMu.Unlock()
	if okCancel {
		cancel()
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func ruleFromOpExact(ruleID string, op rules.Op) (rules.Rule, bool) {
	switch op.Type {
	case "cmd.run":
		var p struct {
			Argv []string `json:"argv"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil || len(p.Argv) == 0 {
			return rules.Rule{}, false
		}
		return rules.Rule{ID: ruleID, OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: p.Argv}}, true
	case "fs.read":
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil || p.Path == "" {
			return rules.Rule{}, false
		}
		return rules.Rule{ID: ruleID, OpType: "fs.read", Path: &rules.PathRule{Exact: p.Path}}, true
	default:
		return rules.Rule{}, false
	}
}

func riskFlags(op rules.Op) []string {
	var flags []string
	switch op.Type {
	case "cmd.run":
		var p struct {
			Argv []string `json:"argv"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if len(p.Argv) > 0 {
			bin := p.Argv[0]
			switch bin {
			case "iptables", "nft", "ufw":
				flags = append(flags, "FIREWALL")
			case "rm", "/bin/rm":
				flags = append(flags, "DESTRUCTIVE_FS")
			}
			if bin == "apt" || bin == "apt-get" {
				for _, a := range p.Argv[1:] {
					if a == "remove" || a == "purge" {
						flags = append(flags, "APT_REMOVE")
						break
					}
					if a == "install" {
						flags = append(flags, "APT_INSTALL")
					}
				}
			}
			if bin == "systemctl" {
				for i := 1; i < len(p.Argv); i++ {
					if (p.Argv[i] == "stop" || p.Argv[i] == "disable") && i+1 < len(p.Argv) {
						unit := p.Argv[i+1]
						if strings.Contains(unit, "ssh") {
							flags = append(flags, "SERVICE_SSH_RISK")
							break
						}
					}
				}
			}
		}
	case "fs.patch_unified", "conf.set_kv":
		var p struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if strings.HasPrefix(p.Path, "/etc/") {
			flags = append(flags, "WRITE_ETC")
		}
	}
	return flags
}

func isDangerous(flags []string) bool {
	for _, f := range flags {
		switch f {
		case "WRITE_ETC", "APT_REMOVE", "FIREWALL", "DESTRUCTIVE_FS", "SERVICE_SSH_RISK":
			return true
		}
	}
	return false
}

func summarizeOp(rec requestRecord) string {
	var op rules.Op
	if err := json.Unmarshal(rec.Op, &op); err != nil {
		return rec.ID + " <invalid op>"
	}
	switch op.Type {
	case "cmd.run":
		var p struct {
			Argv []string `json:"argv"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if len(p.Argv) == 0 {
			return "cmd.run <empty argv>"
		}
		return "cmd.run " + strings.Join(p.Argv, " ")
	default:
		return op.Type
	}
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
	rest := strings.TrimPrefix(r.URL.Path, "/v1/requests/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found", "")
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
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
		return
	}

	if len(parts) == 2 && parts[1] == "decision" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
			return
		}
		a.handleDecision(w, r, c, id)
		return
	}

	if len(parts) == 2 && parts[1] == "kill" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
			return
		}
		a.handleKill(w, r, c, id)
		return
	}

	writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found", id)
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
