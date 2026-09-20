package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/store"
)

func openSession(t *testing.T, s *Server, clientID string) (token string, expiresAt time.Time, sessionID string) {
	t.Helper()

	body := []byte(`{"client_id":"` + clientID + `","pairing_code":"` + s.PairingCode() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	s.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("open status=%d body=%s", rw.Code, rw.Body.String())
	}

	var resp struct {
		SessionID    string `json:"session_id"`
		SessionToken string `json:"session_token"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode open response: %v", err)
	}
	if resp.SessionToken == "" || resp.SessionID == "" {
		t.Fatalf("incomplete open response: %s", rw.Body.String())
	}
	exp, err := time.Parse(time.RFC3339Nano, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at %q: %v", resp.ExpiresAt, err)
	}
	return resp.SessionToken, exp, resp.SessionID
}

func TestServerRestoresAuthTokensAcrossRestart(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "racg.db")

	cfg := config.Defaults()
	cfg.DBPath = dbPath

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, exp1, sessionID := openSession(t, s1, "codex-home")

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	// The token must be persisted in hashed form.
	rows, err := st.ListAuthTokens(ctx)
	if err != nil {
		t.Fatalf("ListAuthTokens: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("persisted tokens=%d, want 1", len(rows))
	}
	if rows[0].TokenHash != auth.HashToken(token) {
		t.Fatalf("persisted hash mismatch: %q", rows[0].TokenHash)
	}
	if rows[0].SessionID != sessionID || rows[0].ClientID != "codex-home" {
		t.Fatalf("persisted claims = %+v", rows[0])
	}
	if !rows[0].ExpiresAt.Equal(exp1) {
		t.Fatalf("persisted expiry=%v, want %v", rows[0].ExpiresAt, exp1)
	}

	// "Restart": a new server over the same DB must accept the old token.
	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("restart New: %v", err)
	}

	meReq := httptest.NewRequest(http.MethodGet, "http://example/v1/session/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+token)
	meRW := httptest.NewRecorder()
	s2.Handler().ServeHTTP(meRW, meReq)
	if meRW.Code != 200 {
		t.Fatalf("session/me status=%d body=%s", meRW.Code, meRW.Body.String())
	}
	var me struct {
		SessionID string `json:"session_id"`
		ClientID  string `json:"client_id"`
	}
	if err := json.Unmarshal(meRW.Body.Bytes(), &me); err != nil {
		t.Fatalf("decode me response: %v", err)
	}
	if me.SessionID != sessionID || me.ClientID != "codex-home" {
		t.Fatalf("me claims = %+v", me)
	}

	// Restored tokens carry no TTL: they stay valid until the restored
	// expiry but no longer slide (documented in internal/auth/tokens.go).
}

func TestServerRevokeDropsPersistedToken(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "racg.db")

	cfg := config.Defaults()
	cfg.DBPath = dbPath

	s1, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, _, _ := openSession(t, s1, "codex-home")

	// Revoke through the server's live token manager.
	if !s1.Tokens().Revoke(token) {
		t.Fatalf("Revoke=false, want true")
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	rows, err := st.ListAuthTokens(ctx)
	if err != nil {
		t.Fatalf("ListAuthTokens: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("tokens=%+v, want empty after revoke", rows)
	}

	// A restarted server must not accept the revoked token.
	s2, err := New(cfg)
	if err != nil {
		t.Fatalf("restart New: %v", err)
	}
	meReq := httptest.NewRequest(http.MethodGet, "http://example/v1/session/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+token)
	meRW := httptest.NewRecorder()
	s2.Handler().ServeHTTP(meRW, meReq)
	if meRW.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token accepted after restart: status=%d", meRW.Code)
	}
}
