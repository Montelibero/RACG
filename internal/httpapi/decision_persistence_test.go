package httpapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/executor"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

type decisionProbeRunner struct{ called chan struct{} }

func (r decisionProbeRunner) Run(context.Context, executor.Spec) executor.Result {
	r.called <- struct{}{}
	return executor.Result{Status: "SUCCEEDED"}
}

func TestLocalDecisionPersistenceFailureHasNoSideEffects(t *testing.T) {
	for _, action := range []string{"DENY", "ALLOW_ONCE", "ALLOW_SESSION", "ALLOW_ALWAYS"} {
		t.Run(action, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			called := make(chan struct{}, 1)
			api := New(config.Defaults(), WithStore(st), WithExecutor(decisionProbeRunner{called}))
			op := rules.Op{Type: "cmd.run", Payload: json.RawMessage(`{"argv":["/bin/echo","hello"]}`)}
			encoded, err := json.Marshal(op)
			if err != nil {
				t.Fatal(err)
			}
			api.reqs["request"] = requestRecord{ID: "request", Status: "PENDING_APPROVAL", SessionID: "session", ClientID: "client", Op: encoded}
			events, cancel := api.SubscribeEvents(10)
			defer cancel()
			if err := api.DecideForTUI("request", action); err == nil {
				t.Fatal("persistence error swallowed")
			}
			info, ok := api.GetRequestInfoForTUI("request")
			if !ok || info.Status != "PENDING_APPROVAL" || info.Decision != nil || info.Result != nil {
				t.Fatalf("request changed: %+v", info)
			}
			if len(api.ListSessionRulesForTUI()) != 0 {
				t.Fatal("session rule installed")
			}
			if _, allowed := api.rules.Match("session", op); allowed {
				t.Fatal("auto-approval rule installed")
			}
			select {
			case <-called:
				t.Fatal("command dispatched after failed persistence")
			case event := <-events:
				t.Fatalf("event published: %+v", event)
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
}
