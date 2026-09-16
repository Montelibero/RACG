package authority

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"sync"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
)

func TestCancellationCancelsPendingOnlyBeforeDispatch(t *testing.T) {
	a, _, _, _, _ := authorityFixture(t)
	ctx := context.Background()
	submission, agentKey := agentSubmission(t, a)
	request, err := a.Submit(ctx, submission)
	if err != nil {
		t.Fatal(err)
	}
	cancellation, err := approval.NewCancellation("server", "agent", request.Request.RequestID, submission.Submission.Nonce, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignCancellation(cancellation, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.CancelSubmission(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyCancellationResult(cancellation, result, a.PublicKey(), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if !result.Result.Canceled || result.Result.Status != "CANCELED" {
		t.Fatalf("pending result=%+v", result.Result)
	}
	called := false
	if _, err := a.ExecuteStored(ctx, request.Request.RequestID, OperationExecutionOptions{}); err == nil || called {
		t.Fatal("canceled pending operation dispatched")
	}
}

func TestCancellationCancelsAuthorizedBeforeClaim(t *testing.T) {
	a, _, _, deviceKey, _ := authorityFixture(t)
	ctx := context.Background()
	submission, agentKey := agentSubmission(t, a)
	request, err := a.Submit(ctx, submission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, request.Request.RequestID, signedDecision(t, request.Request, deviceKey, "ALLOW_ONCE")); err != nil {
		t.Fatal(err)
	}
	cancellation, err := approval.NewCancellation("server", "agent", request.Request.RequestID, submission.Submission.Nonce, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignCancellation(cancellation, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.CancelSubmission(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Result.Canceled || result.Result.Status != "CANCELED" {
		t.Fatalf("authorized result=%+v", result.Result)
	}
	called := false
	if _, err := a.ExecuteStored(ctx, request.Request.RequestID, OperationExecutionOptions{}); err == nil || called {
		t.Fatal("canceled authorized operation dispatched")
	}
}

func TestCancellationNeverClaimsRunningJobKilled(t *testing.T) {
	a, _, _, deviceKey, _ := authorityFixture(t)
	ctx := context.Background()
	submission, agentKey := agentSubmission(t, a)
	request, err := a.Submit(ctx, submission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, request.Request.RequestID, signedDecision(t, request.Request, deviceKey, "ALLOW_ONCE")); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var closeEntered sync.Once
	executionDone := make(chan error, 1)
	go func() {
		_, err := a.Execute(ctx, request.Request.RequestID, func(_ context.Context, got approval.Request) executor.Result {
			closeEntered.Do(func() { close(entered) })
			if string(got.Operation) != string(request.Request.Operation) {
				return executor.Result{
					Status: "FAILED",
					Stderr: errors.New("frozen payload mismatch").Error(),
				}
			}
			<-release
			return executor.Result{Status: "SUCCEEDED"}
		})
		executionDone <- err
	}()
	go func() {
		deadline := time.Now().Add(time.Second)
		for {
			_, status, err := a.Request(ctx, request.Request.RequestID)
			if err != nil {
				executionDone <- err
				return
			}
			if status == "EXECUTING" {
				closeEntered.Do(func() { close(entered) })
				return
			}
			if time.Now().After(deadline) {
				executionDone <- context.DeadlineExceeded
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	<-entered
	cancellation, err := approval.NewCancellation("server", "agent", request.Request.RequestID, submission.Submission.Nonce, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignCancellation(cancellation, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.CancelSubmission(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if result.Result.Canceled || result.Result.Status != "EXECUTING" {
		t.Fatalf("running result=%+v", result.Result)
	}
	close(release)
	if err := <-executionDone; err != nil {
		t.Fatal(err)
	}
	_, status, err := a.Request(ctx, request.Request.RequestID)
	if err != nil || status != "SUCCEEDED" {
		t.Fatalf("running final=%s err=%v", status, err)
	}
	if strings.Contains(strings.ToLower(status), "cancel") {
		t.Fatalf("running job falsely claimed canceled: %s", status)
	}
}

func TestCancellationRejectsForeignAndRevokedAgents(t *testing.T) {
	a, _, _, _, _ := authorityFixture(t)
	ctx := context.Background()
	submission, agentKey := agentSubmission(t, a)
	request, err := a.Submit(ctx, submission)
	if err != nil {
		t.Fatal(err)
	}
	cancellation, err := approval.NewCancellation("server", "other", request.Request.RequestID, submission.Submission.Nonce, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignCancellation(cancellation, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CancelSubmission(ctx, signed); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("foreign cancellation err=%v", err)
	}
	if err := a.RevokeAgentTrusted(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	local, err := approval.NewCancellation("server", "agent", request.Request.RequestID, submission.Submission.Nonce, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedLocal, err := approval.SignCancellation(local, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CancelSubmission(ctx, signedLocal); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked cancellation err=%v", err)
	}
}
