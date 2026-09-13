package authority

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
)

// LookupSubmission is read-only recovery. It authenticates the current agent
// key and scopes the lookup to that agent even if another nonce is known.
// It never creates, approves, cancels or reruns an operation.
func (a *Authority) LookupSubmission(ctx context.Context, signed approval.SignedLookup) (approval.SignedLookupResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	q := signed.Lookup
	var key []byte
	var revoked int
	if err := a.db.QueryRowContext(ctx, "SELECT public_key,revoked FROM authority_agents WHERE client_id=?", q.ClientID).Scan(&key, &revoked); err != nil {
		return approval.SignedLookupResult{}, fmt.Errorf("agent is not enrolled: %w", err)
	}
	if revoked != 0 {
		return approval.SignedLookupResult{}, errors.New("agent revoked")
	}
	if err := approval.VerifyLookup(signed, a.serverID, q.ClientID, ed25519.PublicKey(key), a.now().UTC()); err != nil {
		return approval.SignedLookupResult{}, err
	}
	var data []byte
	var status string
	err := a.db.QueryRowContext(ctx, "SELECT r.envelope,r.status FROM authority_submissions s JOIN authority_requests r ON r.request_id=s.request_id WHERE s.client_id=? AND s.nonce=?", q.ClientID, q.SubmissionNonce).Scan(&data, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.SignLookupResult(q, nil, "", nil, nil, a.key)
	}
	if err != nil {
		return approval.SignedLookupResult{}, err
	}
	var request approval.SignedRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return approval.SignedLookupResult{}, err
	}
	if err := approval.VerifyRequest(request, a.serverID, a.key.Public().(ed25519.PublicKey)); err != nil {
		return approval.SignedLookupResult{}, err
	}
	if request.Request.ClientID != q.ClientID {
		return approval.SignedLookupResult{}, errors.New("stored submission owner mismatch")
	}
	var executionData []byte
	if err := a.db.QueryRowContext(ctx, "SELECT result FROM authority_executions WHERE request_id=?", request.Request.RequestID).Scan(&executionData); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return approval.SignedLookupResult{}, err
	}
	var execution *approval.ExecutionResult
	switch status {
	case "SUCCEEDED", "FAILED", "KILLED", "TIMED_OUT":
		if len(executionData) == 0 {
			return approval.SignedLookupResult{}, errors.New("terminal execution missing result")
		}
		var stored executor.Result
		if err := json.Unmarshal(executionData, &stored); err != nil {
			return approval.SignedLookupResult{}, err
		}
		execution = &approval.ExecutionResult{
			Status:          stored.Status,
			ExitCode:        stored.ExitCode,
			DurationMs:      stored.DurationMs,
			Stdout:          stored.Stdout,
			Stderr:          stored.Stderr,
			StdoutTruncated: stored.StdoutTruncated,
			StderrTruncated: stored.StderrTruncated,
			StdoutSHA256:    stored.StdoutSHA256,
			StderrSHA256:    stored.StderrSHA256,
		}
	}
	var download *approval.DownloadArtifact
	var operation struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(request.Request.Operation, &operation); err != nil {
		return approval.SignedLookupResult{}, err
	}
	if status == "SUCCEEDED" && operation.Type == "fs.download" {
		download = &approval.DownloadArtifact{}
		if err := a.db.QueryRowContext(ctx, "SELECT name,size,sha256,mode,data FROM authority_download_artifacts WHERE request_id=?", request.Request.RequestID).
			Scan(&download.Name, &download.Size, &download.SHA256, &download.Mode, &download.Data); err != nil {
			return approval.SignedLookupResult{}, err
		}
	}
	return approval.SignLookupResult(q, &request, status, execution, download, a.key)
}
