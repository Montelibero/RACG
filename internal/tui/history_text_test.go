package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/store"
)

func TestRenderSessionHistoryTextShowsHumanReadableOperations(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if err := st.InsertSession(ctx, store.Session{ID: "sess1", StartedAt: time.Unix(1000, 0).UTC()}); err != nil {
		t.Fatalf("InsertSession: %v", err)
	}
	if err := st.InsertRequest(ctx, store.Request{
		ID:            "req1",
		SessionID:     "sess1",
		ClientID:      "codex-home",
		Status:        "FINISHED",
		OpJSON:        `{"type":"cmd.run","payload":{"argv":["docker","ps"]}}`,
		RiskFlagsJSON: `[]`,
		CreatedAt:     time.Unix(1001, 0).UTC(),
	}); err != nil {
		t.Fatalf("InsertRequest: %v", err)
	}
	if err := st.InsertDecision(ctx, store.Decision{
		RequestID:      "req1",
		Decision:       "ALLOW_ONCE",
		DecisionSource: "tui",
		DecidedAt:      time.Unix(1002, 0).UTC(),
	}); err != nil {
		t.Fatalf("InsertDecision: %v", err)
	}
	if err := st.InsertExecution(ctx, store.Execution{
		RequestID:       "req1",
		StartedAt:       time.Unix(1003, 0).UTC(),
		FinishedAt:      time.Unix(1004, 0).UTC(),
		DurationMs:      1000,
		ExitCode:        0,
		Status:          "SUCCEEDED",
		Stdout:          "ok\n",
		Stderr:          "",
		StdoutTruncated: false,
		StderrTruncated: false,
		StdoutSHA256:    "x",
		StderrSHA256:    "y",
	}); err != nil {
		t.Fatalf("InsertExecution: %v", err)
	}

	got := renderSessionHistoryText(st, store.Session{ID: "sess1", StartedAt: time.Unix(1000, 0).UTC()})

	for _, want := range []string{
		"session_id: sess1",
		"operations: 1",
		"cmd.run docker ps",
		"decision: ALLOW_ONCE",
		"result: SUCCEEDED",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("history text missing %q:\n%s", want, got)
		}
	}
}
