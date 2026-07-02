package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

func TestServerLoadsAlwaysRulesFromSQLiteOnStart(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "racg.db")

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	if err := st.InsertAlwaysRule(ctx, rules.Rule{
		ID:     "allow-echo",
		OpType: "cmd.run",
		Cmd:    &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("InsertAlwaysRule: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	cfg := config.Defaults()
	cfg.DBPath = dbPath

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Store().Close()

	openBody := []byte(`{"client_id":"codex-home","pairing_code":"` + s.PairingCode() + `"}`)
	openReq := httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(openBody))
	openReq.Header.Set("Content-Type", "application/json")
	openRW := httptest.NewRecorder()
	s.Handler().ServeHTTP(openRW, openReq)
	if openRW.Code != 200 {
		t.Fatalf("open status=%d body=%s", openRW.Code, openRW.Body.String())
	}

	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(openRW.Body.Bytes(), &openResp)
	if openResp.SessionToken == "" {
		t.Fatalf("missing token")
	}

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	s.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("requests status=%d body=%s", rw.Code, rw.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got["status"] != "APPROVED" {
		t.Fatalf("status=%v body=%s", got["status"], rw.Body.String())
	}

	// Ensure DB file exists (not in-memory).
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("db stat: %v", err)
	}
}
