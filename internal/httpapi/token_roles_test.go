package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/store"
)

func TestTokenRolesIsolateAgentRequests(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)
	api := New(config.Defaults(), WithPairing(pair), WithTokenManager(tm), WithStore(st))

	// The pairing flow mints agent tokens.
	agentToken := openTestSession(t, api, pair, "agent-one")
	pair.Regenerate()
	agentTwo := openTestSession(t, api, pair, "agent-two")
	opToken, _ := tm.IssueWithRole("sess-op", "operator-console", time.Hour, auth.RoleOperator)

	clk.Advance(time.Second)
	owned := createTestRequest(t, api, agentToken)

	var me struct {
		Role string `json:"role"`
	}
	meReq := httptest.NewRequest(http.MethodGet, "http://example/v1/session/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+agentToken)
	meRW := httptest.NewRecorder()
	api.Handler().ServeHTTP(meRW, meReq)
	if meRW.Code != 200 || json.Unmarshal(meRW.Body.Bytes(), &me) != nil || me.Role != auth.RoleAgent {
		t.Fatalf("session/me role: %d %s", meRW.Code, meRW.Body.String())
	}

	do := func(token, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://example"+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rw := httptest.NewRecorder()
		api.Handler().ServeHTTP(rw, req)
		return rw
	}

	// Another agent gets 404 for detail, logs, and kill — the request's
	// existence is not revealed.
	if rw := do(agentTwo, http.MethodGet, "/v1/requests/"+owned); rw.Code != http.StatusNotFound {
		t.Fatalf("foreign detail: %d %s", rw.Code, rw.Body.String())
	}
	if rw := do(agentTwo, http.MethodGet, "/v1/requests/"+owned+"/logs/stdout"); rw.Code != http.StatusNotFound {
		t.Fatalf("foreign logs: %d %s", rw.Code, rw.Body.String())
	}
	if rw := do(agentTwo, http.MethodPost, "/v1/requests/"+owned+"/kill"); rw.Code != http.StatusNotFound {
		t.Fatalf("foreign kill: %d %s", rw.Code, rw.Body.String())
	}

	// The owner still reaches the request.
	if rw := do(agentToken, http.MethodGet, "/v1/requests/"+owned); rw.Code != http.StatusOK {
		t.Fatalf("own detail: %d %s", rw.Code, rw.Body.String())
	}

	// The operator audits everything.
	if rw := do(opToken, http.MethodGet, "/v1/requests/"+owned); rw.Code != http.StatusOK {
		t.Fatalf("operator detail: %d %s", rw.Code, rw.Body.String())
	}

	// The agent list stays session-scoped even without the query param.
	clk.Advance(time.Second)
	foreign := createTestRequest(t, api, agentTwo)
	rw := do(agentToken, http.MethodGet, "/v1/requests")
	if rw.Code != http.StatusOK {
		t.Fatalf("agent list: %d %s", rw.Code, rw.Body.String())
	}
	var listResp struct {
		Requests []map[string]any `json:"requests"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	for _, rec := range listResp.Requests {
		if rec["request_id"] == foreign {
			t.Fatalf("agent list leaked foreign request %s", foreign)
		}
	}

	// An agent kills its own pending request.
	if rw := do(agentToken, http.MethodPost, "/v1/requests/"+owned+"/kill"); rw.Code != http.StatusOK {
		t.Fatalf("own kill: %d %s", rw.Code, rw.Body.String())
	}
	rw = do(agentToken, http.MethodGet, "/v1/requests/"+owned)
	var killed struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rw.Body.Bytes(), &killed)
	if killed.Status != "CANCELED" {
		t.Fatalf("killed status=%s", killed.Status)
	}
}

func TestApproverRequestKillStopsRunningRequest(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	tokens := auth.NewTokenManager(auth.RealClock{})
	agentToken, _ := tokens.Issue("session", "client", time.Hour)
	api := New(config.Defaults(), WithStore(st), WithTokenManager(tokens))

	device := newApproverTestDevice(t, "dev1")
	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}

	// A genuinely long-running request through the real executor.
	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["sleep","30"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+agentToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRW := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRW, createReq)
	if createRW.Code > 300 {
		t.Fatalf("create: %d %s", createRW.Code, createRW.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRW.Body.Bytes(), &created)
	pending := api.PendingForApprover()[0]
	if pending.ID != created.RequestID {
		t.Fatalf("pending=%s created=%s", pending.ID, created.RequestID)
	}

	if rw := serveApprover(t, api, device.decisionRequest(t, api, api.serverName, pending.ID, pending.OpSHA256, "ALLOW_ONCE")); rw.Code != http.StatusOK {
		t.Fatalf("decision: %d %s", rw.Code, rw.Body.String())
	}

	waitForStatus := func(want ...string) string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			api.reqsMu.Lock()
			status := api.reqs[created.RequestID].Status
			api.reqsMu.Unlock()
			for _, w := range want {
				if status == w {
					return status
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		api.reqsMu.Lock()
		status := api.reqs[created.RequestID].Status
		api.reqsMu.Unlock()
		t.Fatalf("request never reached %v: %s", want, status)
		return ""
	}
	waitForStatus("RUNNING")

	// Unsigned kill must be rejected.
	if rw := serveApprover(t, api, httptest.NewRequest(http.MethodPost, "/v1/approver/request/kill", strings.NewReader(`{"device_id":"dev1","action":"request.kill","target_id":"`+created.RequestID+`"}`))); rw.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned kill: %d %s", rw.Code, rw.Body.String())
	}

	kill := serveApprover(t, api, device.adminRequest(t, api, "request.kill", created.RequestID, "/v1/approver/request/kill"))
	if kill.Code != http.StatusOK {
		t.Fatalf("signed kill: %d %s", kill.Code, kill.Body.String())
	}
	if final := waitForStatus("KILLED", "FAILED", "CANCELED", "TIMED_OUT"); final == "" {
		t.Fatal("request not terminal after approver kill")
	}

	// Killing an unknown request is a plain 404; killing the finished one
	// reports already_finished instead of mutating anything.
	if rw := serveApprover(t, api, device.adminRequest(t, api, "request.kill", "no-such-request", "/v1/approver/request/kill")); rw.Code != http.StatusNotFound {
		t.Fatalf("unknown kill: %d %s", rw.Code, rw.Body.String())
	}
	again := serveApprover(t, api, device.adminRequest(t, api, "request.kill", created.RequestID, "/v1/approver/request/kill"))
	if again.Code != http.StatusOK || !bytes.Contains(again.Body.Bytes(), []byte(`"already_finished":true`)) {
		t.Fatalf("repeat kill: %d %s", again.Code, again.Body.String())
	}
}
