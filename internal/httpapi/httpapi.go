package httpapi

import (
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
	"github.com/itolstov/racg/internal/version"
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

type API struct {
	cfg config.Config

	pairing *auth.Pairing
	tokens  *auth.TokenManager

	mu             sync.Mutex
	lockedClientIP string

	reqsMu sync.Mutex
	reqs   map[string]requestRecord
}

type requestRecord struct {
	ID     string          `json:"request_id"`
	Status string          `json:"status"`
	Op     json.RawMessage `json:"op"`
}

func New(cfg config.Config, opts ...Option) *API {
	a := &API{cfg: cfg, reqs: map[string]requestRecord{}}

	a.pairing = auth.NewPairing(6, time.Duration(cfg.PairingCodeTTLSeconds)*time.Second, auth.RealClock{})
	a.tokens = auth.NewTokenManager(auth.RealClock{})

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

	return mux
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
		Op          any    `json:"op"`
		ClientReqID string `json:"client_req_id"`
	}
	if err := decodeJSON(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error(), "")
		return
	}

	opBytes, err := json.Marshal(req.Op)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid op", "")
		return
	}

	id := uuid.NewString()
	rec := requestRecord{ID: id, Status: "PENDING_APPROVAL", Op: opBytes}
	a.reqsMu.Lock()
	a.reqs[id] = rec
	a.reqsMu.Unlock()

	resp := map[string]any{"request_id": id, "status": rec.Status}
	writeJSON(w, http.StatusOK, resp)
}

type authHandler func(http.ResponseWriter, *http.Request, auth.Claims)

func (a *API) withAuth(next authHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r.Header.Get("Authorization"))
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing bearer token", "")
			return
		}
		claims, err := a.tokens.Verify(tok)
		if err != nil {
			code, status := mapAuthErr(err)
			writeError(w, status, code, code, "")
			return
		}
		next(w, r, claims)
	}
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
