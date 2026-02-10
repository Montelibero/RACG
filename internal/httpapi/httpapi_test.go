package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/executor"
	"github.com/itolstov/racg/internal/rules"
)

func TestInfo(t *testing.T) {
	api := New(config.Defaults())
	req := httptest.NewRequest(http.MethodGet, "http://example/v1/info", nil)
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d", rw.Code)
	}

	var got map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got["server_version"] == "" {
		t.Fatalf("missing server_version")
	}
}

func TestSessionOpenAndMe(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	body := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}

	var resp struct {
		SessionID    string `json:"session_id"`
		SessionToken string `json:"session_token"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.SessionToken == "" {
		t.Fatalf("empty token")
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://example/v1/session/me", nil)
	req2.Header.Set("Authorization", "Bearer "+resp.SessionToken)
	rw2 := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw2, req2)
	if rw2.Code != 200 {
		t.Fatalf("me status=%d body=%s", rw2.Code, rw2.Body.String())
	}
}

func TestRequestsCreateRequiresAuth(t *testing.T) {
	api := New(config.Defaults())

	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader([]byte(`{"op":{"type":"cmd.run","payload":{}}}`)))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 401 {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestRequestsCreate(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got["request_id"] == "" {
		t.Fatalf("missing request_id")
	}
	if got["status"] != "PENDING_APPROVAL" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestRequestsCreateAutoApproveByRule(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	re := rules.NewEngine()
	re.AddAlways(rules.Rule{ID: "allow-echo", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithRulesEngine(re))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got["status"] != "APPROVED" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestRequestsGetByID(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("create status=%d body=%s", rw.Code, rw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(rw.Body.Bytes(), &created)

	getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID, nil)
	getReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	getRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(getRw, getReq)
	if getRw.Code != 200 {
		t.Fatalf("get status=%d body=%s", getRw.Code, getRw.Body.String())
	}
}

func TestDecisionDeny(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	decBody := []byte(`{"decision":"DENY"}`)
	decReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/decision", bytes.NewReader(decBody))
	decReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	decReq.Header.Set("Content-Type", "application/json")
	decRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(decRw, decReq)
	if decRw.Code != 200 {
		t.Fatalf("dec status=%d body=%s", decRw.Code, decRw.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID, nil)
	getReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	getRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(getRw, getReq)
	if getRw.Code != 200 {
		t.Fatalf("get status=%d body=%s", getRw.Code, getRw.Body.String())
	}
	var rec map[string]any
	_ = json.Unmarshal(getRw.Body.Bytes(), &rec)
	if rec["status"] != "DENIED" {
		t.Fatalf("status=%v", rec["status"])
	}
}

type fakeRunner struct {
	started chan struct{}
	done    chan struct{}
}

func (f *fakeRunner) Run(ctx context.Context, s executor.Spec) executor.Result {
	close(f.started)
	<-ctx.Done()
	close(f.done)
	return executor.Result{Status: "KILLED", ExitCode: -1}
}

func TestKillRunningRequest(t *testing.T) {
	cfg := config.Defaults()
	cfg.DefaultTimeoutSec = 10

	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	fr := &fakeRunner{started: make(chan struct{}), done: make(chan struct{})}

	re := rules.NewEngine()
	re.AddAlways(rules.Rule{ID: "allow-sleep", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/sleep"}}})

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithRulesEngine(re), WithExecutor(fr))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/sleep","2"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	<-fr.started

	killReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/kill", nil)
	killReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	killRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(killRw, killReq)
	if killRw.Code != 200 {
		t.Fatalf("kill status=%d body=%s", killRw.Code, killRw.Body.String())
	}
	<-fr.done
}
