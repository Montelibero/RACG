package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/store"
)

func TestServerRehydratesRequestsAndMarksRunningFailed(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "racg.db")

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	if err := st.InsertSession(ctx, store.Session{ID: "sess1", StartedAt: time.Unix(1000, 0).UTC()}); err != nil {
		t.Fatalf("InsertSession: %v", err)
	}
	mustInsertReq := func(id, status string) {
		t.Helper()
		if err := st.InsertRequest(ctx, store.Request{
			ID:            id,
			SessionID:     "sess1",
			ClientID:      "c1",
			Status:        status,
			OpJSON:        `{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}`,
			RiskFlagsJSON: `[]`,
			CreatedAt:     time.Unix(1001, 0).UTC(),
		}); err != nil {
			t.Fatalf("InsertRequest(%s): %v", id, err)
		}
	}
	mustInsertReq("req-pending", "PENDING_APPROVAL")
	mustInsertReq("req-approved", "APPROVED")
	mustInsertReq("req-running", "RUNNING")

	if err := st.InsertDecision(ctx, store.Decision{
		RequestID:      "req-approved",
		Decision:       "ALLOW_ONCE",
		DecisionSource: "tui",
		DecidedAt:      time.Unix(1002, 0).UTC(),
	}); err != nil {
		t.Fatalf("InsertDecision: %v", err)
	}
	if err := st.InsertDecision(ctx, store.Decision{
		RequestID:      "req-running",
		Decision:       "ALLOW_ONCE",
		DecisionSource: "tui",
		DecidedAt:      time.Unix(1002, 0).UTC(),
	}); err != nil {
		t.Fatalf("InsertDecision2: %v", err)
	}
	_ = st.Close()

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
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(openRW.Body.Bytes(), &openResp)

	get := func(id string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
		rw := httptest.NewRecorder()
		s.Handler().ServeHTTP(rw, req)
		if rw.Code != 200 {
			t.Fatalf("get %s status=%d body=%s", id, rw.Code, rw.Body.String())
		}
		var rec map[string]any
		_ = json.Unmarshal(rw.Body.Bytes(), &rec)
		return rec
	}

	if got := get("req-pending")["status"]; got != "PENDING_APPROVAL" {
		t.Fatalf("pending status=%v", got)
	}
	if got := get("req-approved")["status"]; got != "APPROVED" {
		t.Fatalf("approved status=%v", got)
	}

	recRunning := get("req-running")
	if got := recRunning["status"]; got != "FAILED" {
		t.Fatalf("running status=%v", got)
	}
	res, ok := recRunning["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result")
	}
	if res["stderr"] == "" {
		t.Fatalf("stderr empty")
	}

	// Also persisted in SQLite.
	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open2: %v", err)
	}
	defer st2.Close()

	reqRow, err := st2.GetRequest(ctx, "req-running")
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if reqRow.Status != "FAILED" {
		t.Fatalf("db status=%q", reqRow.Status)
	}
	if _, err := st2.GetExecution(ctx, "req-running"); err != nil {
		if err == sql.ErrNoRows {
			t.Fatalf("expected execution row for req-running")
		}
		t.Fatalf("GetExecution: %v", err)
	}
}

