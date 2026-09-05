package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/rules"
)

func pendingDecisionStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err = s.InsertSession(ctx, Session{ID: "session", StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err = s.InsertRequest(ctx, Request{ID: "request", SessionID: "session", ClientID: "client", Status: "PENDING_APPROVAL", OpJSON: `{"type":"cmd.run","payload":{"argv":["echo"]}}`, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestCommitPendingDecisionRollback(t *testing.T) {
	for _, failure := range []string{"decision", "second rule", "context"} {
		t.Run(failure, func(t *testing.T) {
			s, _ := pendingDecisionStore(t)
			ctx := context.Background()
			d := Decision{RequestID: "request", Decision: "ALLOW_ALWAYS", DecisionSource: "tui", DecidedAt: time.Now().UTC()}
			rs := []rules.Rule{{ID: "first", OpType: "fs.read", Path: &rules.PathRule{Exact: "/one"}}, {ID: "second", OpType: "fs.read", Path: &rules.PathRule{Exact: "/two"}}}
			switch failure {
			case "decision":
				if _, err := s.db.Exec("CREATE TRIGGER fail_decision BEFORE INSERT ON decisions BEGIN SELECT RAISE(ABORT, 'test failure'); END"); err != nil {
					t.Fatal(err)
				}
			case "second rule":
				if _, err := s.db.Exec("CREATE TRIGGER fail_rule BEFORE INSERT ON rules WHEN NEW.rule_id = 'second' BEGIN SELECT RAISE(ABORT, 'test failure'); END"); err != nil {
					t.Fatal(err)
				}
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := s.CommitPendingDecision(ctx, d, rs); err == nil {
				t.Fatal("expected failure")
			}
			ctx = context.Background()
			request, err := s.GetRequest(ctx, "request")
			if err != nil || request.Status != "PENDING_APPROVAL" {
				t.Fatalf("request=%+v err=%v", request, err)
			}
			if _, err := s.GetDecision(ctx, "request"); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("decision survived: %v", err)
			}
			stored, err := s.ListRules(ctx, 100)
			if err != nil || len(stored) != 0 {
				t.Fatalf("rules survived: %v %v", stored, err)
			}
		})
	}
}

func TestCommitPendingDecisionSurvivesRestartAndRejectsReplay(t *testing.T) {
	s, path := pendingDecisionStore(t)
	ctx := context.Background()
	d := Decision{RequestID: "request", Decision: "ALLOW_ALWAYS", DecisionSource: "tui", RuleID: "rule", DecidedAt: time.Now().UTC()}
	rs := []rules.Rule{{ID: "rule", OpType: "fs.read", Path: &rules.PathRule{Exact: "/one"}}}
	if err := s.CommitPendingDecision(ctx, d, rs); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.CommitPendingDecision(ctx, d, rs); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("replay=%v", err)
	}
	request, err := reopened.GetRequest(ctx, "request")
	if err != nil || request.Status != "APPROVED" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	decision, err := reopened.GetDecision(ctx, "request")
	if err != nil || decision.RuleID != "rule" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	stored, err := reopened.ListRules(ctx, 100)
	if err != nil || len(stored) != 1 {
		t.Fatalf("rules=%v err=%v", stored, err)
	}
}

func TestCommitPendingDecisionConcurrent(t *testing.T) {
	s, _ := pendingDecisionStore(t)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, action := range []string{"ALLOW_ONCE", "DENY"} {
		wg.Add(1)
		go func(action string) {
			defer wg.Done()
			results <- s.CommitPendingDecision(context.Background(), Decision{RequestID: "request", Decision: action, DecisionSource: "tui", DecidedAt: time.Now().UTC()}, nil)
		}(action)
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrRequestNotPending) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}
