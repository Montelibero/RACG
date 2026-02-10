package store

import (
	"context"
	"testing"
	"time"
)

func TestRequestDecisionExecutionPersistence(t *testing.T) {
	ctx := context.Background()

	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if err := s.InsertSession(ctx, Session{ID: "sess1", StartedAt: time.Unix(1000, 0).UTC()}); err != nil {
		t.Fatalf("InsertSession: %v", err)
	}

	if err := s.InsertRequest(ctx, Request{
		ID:           "req1",
		SessionID:    "sess1",
		ClientID:     "c1",
		Status:       "PENDING_APPROVAL",
		OpJSON:       `{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}`,
		RiskFlagsJSON: `[]`,
		CreatedAt:    time.Unix(1001, 0).UTC(),
	}); err != nil {
		t.Fatalf("InsertRequest: %v", err)
	}

	if err := s.InsertDecision(ctx, Decision{
		RequestID:      "req1",
		Decision:       "ALLOW_ONCE",
		DecisionSource: "tui",
		DecidedAt:      time.Unix(1002, 0).UTC(),
	}); err != nil {
		t.Fatalf("InsertDecision: %v", err)
	}

	if err := s.InsertExecution(ctx, Execution{
		RequestID:        "req1",
		StartedAt:        time.Unix(1003, 0).UTC(),
		FinishedAt:       time.Unix(1004, 0).UTC(),
		DurationMs:       1000,
		ExitCode:         0,
		Status:           "SUCCEEDED",
		Stdout:           "hi\n",
		Stderr:           "",
		StdoutTruncated:  false,
		StderrTruncated:  false,
		StdoutSHA256:     "x",
		StderrSHA256:     "y",
	}); err != nil {
		t.Fatalf("InsertExecution: %v", err)
	}

	gotReq, err := s.GetRequest(ctx, "req1")
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if gotReq.Status != "PENDING_APPROVAL" {
		t.Fatalf("request status=%q", gotReq.Status)
	}

	gotDec, err := s.GetDecision(ctx, "req1")
	if err != nil {
		t.Fatalf("GetDecision: %v", err)
	}
	if gotDec.Decision != "ALLOW_ONCE" {
		t.Fatalf("decision=%q", gotDec.Decision)
	}

	gotExec, err := s.GetExecution(ctx, "req1")
	if err != nil {
		t.Fatalf("GetExecution: %v", err)
	}
	if gotExec.Status != "SUCCEEDED" {
		t.Fatalf("exec status=%q", gotExec.Status)
	}
}

