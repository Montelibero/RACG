package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/store"
)

func TestServerPersistsSessionOnOpen(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "racg.db")

	cfg := config.Defaults()
	cfg.DBPath = dbPath

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	openBody := []byte(`{"client_id":"codex-home","pairing_code":"` + s.PairingCode() + `"}`)
	openReq := httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(openBody))
	openReq.Header.Set("Content-Type", "application/json")
	openRW := httptest.NewRecorder()
	s.Handler().ServeHTTP(openRW, openReq)
	if openRW.Code != 200 {
		t.Fatalf("open status=%d body=%s", openRW.Code, openRW.Body.String())
	}

	var openResp struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(openRW.Body.Bytes(), &openResp)
	if openResp.SessionID == "" {
		t.Fatalf("missing session_id")
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	if _, err := st.GetSession(ctx, openResp.SessionID); err != nil {
		t.Fatalf("GetSession: %v", err)
	}
}

