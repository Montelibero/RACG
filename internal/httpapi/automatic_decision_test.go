package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

func TestAutoApprovalStorageFailureRemainsPending(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertSession(ctx, store.Session{ID: "session", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TRIGGER fail_decision BEFORE INSERT ON decisions BEGIN SELECT RAISE(ABORT, 'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	tokens := auth.NewTokenManager(nil)
	token, _ := tokens.Issue("session", "client", time.Hour)
	called := make(chan struct{}, 1)
	engine := rules.NewEngine()
	engine.AddAlways(rules.Rule{ID: "echo", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})
	api := New(config.Defaults(), WithStore(st), WithTokenManager(tokens), WithRulesEngine(engine), WithExecutor(decisionProbeRunner{called}))
	req := httptest.NewRequest(http.MethodPost, "/v1/requests", strings.NewReader(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hello"]}}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 500 || !strings.Contains(rw.Body.String(), "DECISION_PERSISTENCE_FAILED") {
		t.Fatalf("response=%d %s", rw.Code, rw.Body.String())
	}
	pending := api.ListPendingForTUI()
	if len(pending) != 1 {
		t.Fatalf("pending=%v", pending)
	}
	id := pending[0].ID
	if !strings.Contains(rw.Body.String(), id) {
		t.Fatal("error omitted recoverable request ID")
	}
	saved, err := st.GetRequest(ctx, id)
	if err != nil || saved.Status != "PENDING_APPROVAL" {
		t.Fatalf("saved=%+v err=%v", saved, err)
	}
	if _, err := st.GetDecision(ctx, id); err != sql.ErrNoRows {
		t.Fatalf("decision=%v", err)
	}
	select {
	case <-called:
		t.Fatal("execution after failed auto-approval")
	default:
	}
	// Storage can recover without resubmitting the operation.
	if _, err := db.Exec("DROP TRIGGER fail_decision"); err != nil {
		t.Fatal(err)
	}
	if err := api.DecideForTUI(id, "DENY"); err != nil {
		t.Fatal(err)
	}
	info, _ := api.GetRequestInfoForTUI(id)
	if info.Status != "DENIED" {
		t.Fatalf("info=%+v", info)
	}
}

func TestAutoAndManualApprovalDispatchOnlyOnce(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		called := make(chan struct{}, 2)
		engine := rules.NewEngine()
		engine.AddAlways(rules.Rule{ID: "echo", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})
		api := New(config.Defaults(), WithRulesEngine(engine), WithExecutor(decisionProbeRunner{called}))
		api.reqs["request"] = requestRecord{ID: "request", Status: "PENDING_APPROVAL", SessionID: "session", ClientID: "client", Op: json.RawMessage(`{"type":"cmd.run","payload":{"argv":["/bin/echo","hello"]}}`)}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := api.approveByRule(context.Background(), "request"); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := api.DecideForTUI("request", "ALLOW_ONCE"); err != nil && err.Error() != "REQUEST_NOT_PENDING" {
				t.Error(err)
			}
		}()
		wg.Wait()
		select {
		case <-called:
		case <-time.After(time.Second):
			t.Fatal("missing execution")
		}
		// Wait for the first dispatch to finish, then ensure a repeated rule pass is inert.
		deadline := time.Now().Add(time.Second)
		for {
			info, _ := api.GetRequestInfoForTUI("request")
			if info.Status == "SUCCEEDED" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("execution did not finish")
			}
			time.Sleep(time.Millisecond)
		}
		if status, err := api.approveByRule(context.Background(), "request"); err != nil || status != "SUCCEEDED" {
			t.Fatalf("repeat=%s %v", status, err)
		}
		select {
		case <-called:
			t.Fatal("duplicate dispatch")
		default:
		}
	}
}
