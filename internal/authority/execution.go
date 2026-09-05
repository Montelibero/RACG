package authority

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
)

// RunOperation is installed only by trusted composition. The backend must
// interpret the supplied frozen envelope, not a broker-supplied payload/path.
type RunOperation func(context.Context, approval.Request) executor.Result

// Execute durably claims one authorized request before calling the backend.
// An error after dispatch means execution may have happened; never retry it
// automatically. A cancelled caller context still permits saving the result.
func (a *Authority) Execute(ctx context.Context, id string, run RunOperation) (executor.Result, error) {
	if run == nil {
		return executor.Result{}, errors.New("execution backend required")
	}
	request, err := a.claimExecution(ctx, id)
	if err != nil {
		return executor.Result{}, err
	}
	result := run(ctx, request)
	switch result.Status {
	case "SUCCEEDED", "FAILED", "KILLED", "TIMED_OUT":
	default:
		return executor.Result{}, errors.New("backend returned non-terminal status; execution outcome uncertain")
	}
	data, err := json.Marshal(result)
	if err != nil {
		return executor.Result{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Persist completion independently of a command timeout/cancellation.
	completion := context.WithoutCancel(ctx)
	tx, err := a.db.BeginTx(completion, nil)
	if err != nil {
		return result, fmt.Errorf("execution finished but result persistence failed: %w", err)
	}
	defer tx.Rollback()
	changed, err := tx.ExecContext(completion, "UPDATE authority_requests SET status=? WHERE request_id=? AND status='EXECUTING'", result.Status, id)
	if err != nil {
		return result, err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return result, err
	}
	if n != 1 {
		return result, errors.New("execution state changed; completion not committed")
	}
	if _, err := tx.ExecContext(completion, "UPDATE authority_executions SET result=?,finished_at=? WHERE request_id=?", data, a.now().UTC().Format(time.RFC3339Nano), id); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func (a *Authority) claimExecution(ctx context.Context, id string) (approval.Request, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.Request{}, err
	}
	defer tx.Rollback()
	var envelope, decisionData []byte
	var status string
	if err := tx.QueryRowContext(ctx, "SELECT envelope,status,signed_decision FROM authority_requests WHERE request_id=?", id).Scan(&envelope, &status, &decisionData); err != nil {
		return approval.Request{}, err
	}
	if status != "AUTHORIZED" {
		return approval.Request{}, errors.New("request is not awaiting authorized execution")
	}
	var request approval.SignedRequest
	var decision approval.SignedDecision
	if err := json.Unmarshal(envelope, &request); err != nil {
		return approval.Request{}, err
	}
	if err := json.Unmarshal(decisionData, &decision); err != nil {
		return approval.Request{}, err
	}
	if request.Request.RequestID != id {
		return approval.Request{}, errors.New("stored request identity mismatch")
	}
	if err := approval.VerifyRequest(request, a.serverID, a.key.Public().(ed25519.PublicKey)); err != nil {
		return approval.Request{}, err
	}
	if decision.Decision.Action != "ALLOW_ONCE" {
		return approval.Request{}, errors.New("decision does not authorize one-shot execution")
	}
	var key []byte
	var revoked int
	if err := tx.QueryRowContext(ctx, "SELECT public_key,revoked FROM authority_devices WHERE device_id=?", decision.Decision.DeviceID).Scan(&key, &revoked); err != nil {
		return approval.Request{}, err
	}
	if revoked != 0 {
		return approval.Request{}, errors.New("approver revoked before dispatch")
	}
	now := a.now().UTC()
	if err := approval.VerifyDecision(request.Request, decision, decision.Decision.DeviceID, ed25519.PublicKey(key), now); err != nil {
		return approval.Request{}, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE authority_requests SET status='EXECUTING' WHERE request_id=? AND status='AUTHORIZED'", id)
	if err != nil {
		return approval.Request{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return approval.Request{}, err
	}
	if n != 1 {
		return approval.Request{}, errors.New("execution already claimed")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO authority_executions(request_id,started_at) VALUES(?,?)", id, now.Format(time.RFC3339Nano)); err != nil {
		return approval.Request{}, err
	}
	if err := tx.Commit(); err != nil {
		return approval.Request{}, err
	}
	return request.Request, nil
}

// RecoverInterruptedTrusted runs only at startup after obtaining exclusive
// process ownership, before accepting traffic or dispatching jobs. A process
// crash may leave external effects or orphaned children; uncertainty is not
// failure and must never cause an automatic rerun.
func (a *Authority) RecoverInterruptedTrusted(ctx context.Context) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	result, err := a.db.ExecContext(ctx, "UPDATE authority_requests SET status='UNCERTAIN' WHERE status='EXECUTING'")
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
