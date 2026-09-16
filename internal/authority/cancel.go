package authority

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/itolstov/racg/internal/approval"
)

// CancelSubmission durably cancels a request only before execution dispatch.
// A request already claimed by the trusted executor is not touched: this
// boundary cannot honestly claim that external side effects were killed.
func (a *Authority) CancelSubmission(ctx context.Context, signed approval.SignedCancellation) (approval.SignedCancellationResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := signed.Cancellation
	var key []byte
	var revoked int
	if err := a.db.QueryRowContext(ctx, "SELECT public_key,revoked FROM authority_agents WHERE client_id=?", c.ClientID).Scan(&key, &revoked); err != nil {
		return approval.SignedCancellationResult{}, fmt.Errorf("agent is not enrolled: %w", err)
	}
	if revoked != 0 {
		return approval.SignedCancellationResult{}, errors.New("agent revoked")
	}
	if err := approval.VerifyCancellation(signed, a.serverID, c.ClientID, c.RequestID, ed25519.PublicKey(key), a.now().UTC()); err != nil {
		return approval.SignedCancellationResult{}, err
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.SignedCancellationResult{}, err
	}
	defer tx.Rollback()
	var data []byte
	var status string
	err = tx.QueryRowContext(ctx,
		`SELECT r.envelope,r.status
		   FROM authority_submissions s
		   JOIN authority_requests r ON r.request_id=s.request_id
		  WHERE s.client_id=? AND s.nonce=?`,
		c.ClientID, c.SubmissionNonce).Scan(&data, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.SignCancellationResult(c, "NOT_FOUND", false, a.key)
	}
	if err != nil {
		return approval.SignedCancellationResult{}, err
	}
	var request approval.SignedRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return approval.SignedCancellationResult{}, err
	}
	if err := approval.VerifyRequest(request, a.serverID, a.key.Public().(ed25519.PublicKey)); err != nil {
		return approval.SignedCancellationResult{}, err
	}
	if request.Request.ClientID != c.ClientID || request.Request.RequestID != c.RequestID {
		return approval.SignedCancellationResult{}, errors.New("cancellation request identity mismatch")
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE authority_requests SET status='CANCELED' WHERE request_id=? AND status IN ('PENDING_APPROVAL','AUTHORIZED')",
		request.Request.RequestID)
	if err != nil {
		return approval.SignedCancellationResult{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return approval.SignedCancellationResult{}, err
	}
	if changed == 1 {
		encoded, err := json.Marshal(signed)
		if err != nil {
			return approval.SignedCancellationResult{}, err
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO authority_cancellations(request_id,nonce,cancellation) VALUES(?,?,?)",
			request.Request.RequestID, c.SubmissionNonce, encoded); err != nil {
			return approval.SignedCancellationResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return approval.SignedCancellationResult{}, err
		}
		return approval.SignCancellationResult(c, "CANCELED", true, a.key)
	}
	if err := tx.Commit(); err != nil {
		return approval.SignedCancellationResult{}, err
	}
	canceled := status == "CANCELED"
	return approval.SignCancellationResult(c, status, canceled, a.key)
}
