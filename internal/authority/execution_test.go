package authority

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
)

func TestExecutionClaimsOnceAndUsesFrozenPayload(t *testing.T) {
	a, _, _, key, r := authorityFixture(t)
	ctx := context.Background()
	if _, err := a.Consume(ctx, r.Request.RequestID, signedDecision(t, r.Request, key, "ALLOW_ONCE")); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var count atomic.Int32
	run := func(ctx context.Context, got approval.Request) executor.Result {
		count.Add(1)
		if string(got.Operation) != string(r.Request.Operation) {
			t.Error("backend did not receive stored operation")
		}
		close(entered)
		<-release
		return executor.Result{Status: "SUCCEEDED", Stdout: "done"}
	}
	go func() { _, err := a.Execute(ctx, r.Request.RequestID, run); done <- err }()
	<-entered
	if _, err := a.Execute(ctx, r.Request.RequestID, run); err == nil {
		t.Fatal("concurrent duplicate execution accepted")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatalf("executions=%d", count.Load())
	}
	if _, err := a.Execute(ctx, r.Request.RequestID, run); err == nil {
		t.Fatal("completed execution repeated")
	}
	var data []byte
	if err := a.db.QueryRow("SELECT result FROM authority_executions WHERE request_id=?", r.Request.RequestID).Scan(&data); err != nil {
		t.Fatal(err)
	}
	var saved executor.Result
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Status != "SUCCEEDED" || saved.Stdout != "done" {
		t.Fatalf("result=%+v", saved)
	}
}

func TestExecutionRejectsMissingOrInvalidAuthority(t *testing.T) {
	for _, state := range []string{"pending", "denied", "expired", "revoked", "claim write fails"} {
		t.Run(state, func(t *testing.T) {
			a, db, _, key, r := authorityFixture(t)
			ctx := context.Background()
			if state != "pending" {
				action := "ALLOW_ONCE"
				if state == "denied" {
					action = "DENY"
				}
				if _, err := a.Consume(ctx, r.Request.RequestID, signedDecision(t, r.Request, key, action)); err != nil {
					t.Fatal(err)
				}
			}
			switch state {
			case "expired":
				a.now = func() time.Time { return time.Unix(1100, 0) }
			case "revoked":
				if err := a.RevokeTrusted(ctx, "desktop"); err != nil {
					t.Fatal(err)
				}
			case "claim write fails":
				if _, err := db.Exec("CREATE TRIGGER fail_claim BEFORE INSERT ON authority_executions BEGIN SELECT RAISE(ABORT,'test failure'); END"); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			_, err := a.Execute(ctx, r.Request.RequestID, func(context.Context, approval.Request) executor.Result {
				called = true
				return executor.Result{Status: "SUCCEEDED"}
			})
			if err == nil || called {
				t.Fatalf("execution called=%v err=%v", called, err)
			}
			if state == "claim write fails" {
				_, status, err := a.Request(ctx, r.Request.RequestID)
				if err != nil || status != "AUTHORIZED" {
					t.Fatalf("claim rollback=%s %v", status, err)
				}
			}
		})
	}
}

func TestInterruptedExecutionIsUncertainAndNeverReplayed(t *testing.T) {
	a, db, server, key, r := authorityFixture(t)
	ctx := context.Background()
	if _, err := a.Consume(ctx, r.Request.RequestID, signedDecision(t, r.Request, key, "ALLOW_ONCE")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.claimExecution(ctx, r.Request.RequestID); err != nil {
		t.Fatal(err)
	}
	// Simulate restart after the durable claim, with no reliable completion.
	reopened, err := New(ctx, db, "server", server, func() time.Time { return time.Unix(1001, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if n, err := reopened.RecoverInterruptedTrusted(ctx); err != nil || n != 1 {
		t.Fatalf("recovery=%d %v", n, err)
	}
	_, status, err := reopened.Request(ctx, r.Request.RequestID)
	if err != nil || status != "UNCERTAIN" {
		t.Fatalf("status=%s err=%v", status, err)
	}
	called := false
	if _, err := reopened.Execute(ctx, r.Request.RequestID, func(context.Context, approval.Request) executor.Result {
		called = true
		return executor.Result{Status: "SUCCEEDED"}
	}); err == nil || called {
		t.Fatal("uncertain operation rerun")
	}
	if n, err := reopened.RecoverInterruptedTrusted(ctx); err != nil || n != 0 {
		t.Fatalf("repeat recovery=%d %v", n, err)
	}
}

func TestExecutionCompletionFailureDoesNotEnableRetry(t *testing.T) {
	a, db, _, key, r := authorityFixture(t)
	ctx := context.Background()
	if _, err := a.Consume(ctx, r.Request.RequestID, signedDecision(t, r.Request, key, "ALLOW_ONCE")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER fail_result BEFORE UPDATE ON authority_executions BEGIN SELECT RAISE(ABORT,'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(ctx, r.Request.RequestID, func(context.Context, approval.Request) executor.Result {
		return executor.Result{Status: "SUCCEEDED", Stdout: "side effect happened"}
	})
	if err == nil || !strings.Contains(result.Stdout, "happened") {
		t.Fatalf("completion=%+v %v", result, err)
	}
	_, status, err := a.Request(ctx, r.Request.RequestID)
	if err != nil || status != "EXECUTING" {
		t.Fatalf("completion transaction rollback=%s %v", status, err)
	}
	if _, err := a.claimExecution(ctx, r.Request.RequestID); err == nil {
		t.Fatal("failed completion permitted retry")
	}
}

func TestCancelledExecutionStillPersistsResult(t *testing.T) {
	a, _, _, key, r := authorityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := a.Consume(ctx, r.Request.RequestID, signedDecision(t, r.Request, key, "ALLOW_ONCE")); err != nil {
		t.Fatal(err)
	}
	_, err := a.Execute(ctx, r.Request.RequestID, func(context.Context, approval.Request) executor.Result {
		cancel()
		return executor.Result{Status: "KILLED"}
	})
	if err != nil {
		t.Fatal(err)
	}
	_, status, err := a.Request(context.Background(), r.Request.RequestID)
	if err != nil || status != "KILLED" {
		t.Fatalf("status=%s err=%v", status, err)
	}
}
