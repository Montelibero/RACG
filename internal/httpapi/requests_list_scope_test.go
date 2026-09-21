package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
)

func openTestSession(t *testing.T, api *API, pair *auth.Pairing, clientID string) string {
	t.Helper()
	body := []byte(`{"client_id":"` + clientID + `","pairing_code":"` + pair.Code() + `"}`)
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(body)))
	if rw.Code != 200 {
		t.Fatalf("open session %s: %d %s", clientID, rw.Code, rw.Body.String())
	}
	var resp struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil || resp.SessionToken == "" {
		t.Fatalf("open session %s body: %s", clientID, rw.Body.String())
	}
	return resp.SessionToken
}

func createTestRequest(t *testing.T, api *API, token string) string {
	t.Helper()
	body := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("create request: %d %s", rw.Code, rw.Body.String())
	}
	var resp struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil || resp.RequestID == "" {
		t.Fatalf("create request body: %s", rw.Body.String())
	}
	return resp.RequestID
}

func TestRequestsListSessionScope(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)
	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	alpha := openTestSession(t, api, pair, "alpha")
	pair.Regenerate()
	beta := openTestSession(t, api, pair, "beta")

	// Two requests per session with distinct creation times.
	clk.Advance(time.Second)
	alphaFirst := createTestRequest(t, api, alpha)
	clk.Advance(time.Second)
	betaFirst := createTestRequest(t, api, beta)
	clk.Advance(time.Second)
	alphaSecond := createTestRequest(t, api, alpha)
	// Operator tokens keep the legacy unscoped audit view.
	opToken, _ := tm.IssueWithRole("sess-op", "op-client", time.Hour, auth.RoleOperator)

	list := func(token, query string) []map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://example/v1/requests"+query, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rw := httptest.NewRecorder()
		api.Handler().ServeHTTP(rw, req)
		if rw.Code != 200 {
			t.Fatalf("list %s: %d %s", query, rw.Code, rw.Body.String())
		}
		var resp struct {
			Requests []map[string]any `json:"requests"`
		}
		if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
			t.Fatalf("list body: %s", rw.Body.String())
		}
		return resp.Requests
	}

	// Each session sees only its own requests, newest first.
	got := list(alpha, "?scope=session")
	if len(got) != 2 {
		t.Fatalf("alpha saw %d requests, want 2: %v", len(got), got)
	}
	if got[0]["request_id"] != alphaSecond || got[1]["request_id"] != alphaFirst {
		t.Fatalf("alpha order wrong: %v", got)
	}
	got = list(beta, "?scope=session")
	if len(got) != 1 || got[0]["request_id"] != betaFirst {
		t.Fatalf("beta saw %v, want only %s", got, betaFirst)
	}

	// Status filter within the session scope.
	got = list(alpha, "?scope=session&status=NO_SUCH_STATUS")
	if len(got) != 0 {
		t.Fatalf("status filter ignored: %v", got)
	}

	// Limit caps the newest-first tail.
	for i := 0; i < 12; i++ {
		clk.Advance(time.Second)
		createTestRequest(t, api, alpha)
	}
	got = list(alpha, "?scope=session")
	if len(got) != 10 {
		t.Fatalf("default limit: %d requests, want 10", len(got))
	}
	wantNewest := ""
	for _, rec := range got {
		created, _ := rec["created_at"].(string)
		if created != "" && created > wantNewest {
			wantNewest = created
		}
	}
	if got[0]["created_at"] != wantNewest {
		t.Fatalf("newest first violated: %v", got[0]["created_at"])
	}
	got = list(alpha, "?scope=session&limit=3")
	if len(got) != 3 {
		t.Fatalf("explicit limit: %d requests, want 3", len(got))
	}

	// Operator tokens keep the legacy unscoped audit view: pending
	// approvals of every session.
	got = list(opToken, "")
	if len(got) != 15 {
		t.Fatalf("legacy unscoped operator list: %d requests, want 15", len(got))
	}
	// An agent cannot widen its view by omitting the scope: the server
	// forces session scope regardless of the query string.
	got = list(alpha, "?status=PENDING_APPROVAL")
	if len(got) > 10 {
		t.Fatalf("agent forced session scope ignored: %d requests", len(got))
	}
}
