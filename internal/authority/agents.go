package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/itolstov/racg/internal/approval"
)

// EnrollAgentTrusted registers a permanent submission credential. This is a
// trusted administrative/SSH operation, never an agent or broker endpoint.
// Keys survive authority restarts and remain valid until revoked or rotated.
// Agent and approver registries are deliberately separate.
func (a *Authority) EnrollAgentTrusted(ctx context.Context, clientID string, key ed25519.PublicKey) error {
	if clientID == "" || len(key) != ed25519.PublicKeySize {
		return errors.New("agent identity and Ed25519 public key required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.db.ExecContext(ctx, "INSERT INTO authority_agents(client_id,public_key,revoked) VALUES(?,?,0) ON CONFLICT(client_id) DO UPDATE SET public_key=excluded.public_key, revoked=0", clientID, []byte(key))
	return err
}

func (a *Authority) RevokeAgentTrusted(ctx context.Context, clientID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	result, err := a.db.ExecContext(ctx, "UPDATE authority_agents SET revoked=1 WHERE client_id=?", clientID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// Submit authenticates agent identity inside the authority and atomically
// freezes one pending request per signed retry nonce. It grants no execution.
// Referenced staged files still require an authority-owned immutable admission
// layer before this method can be connected to a live executor.
func (a *Authority) Submit(ctx context.Context, signed approval.SignedSubmission) (approval.SignedRequest, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	defer tx.Rollback()
	s := signed.Submission
	var key []byte
	var revoked int
	if err := tx.QueryRowContext(ctx, "SELECT public_key,revoked FROM authority_agents WHERE client_id=?", s.ClientID).Scan(&key, &revoked); err != nil {
		return approval.SignedRequest{}, fmt.Errorf("agent is not enrolled: %w", err)
	}
	if revoked != 0 {
		return approval.SignedRequest{}, errors.New("agent revoked")
	}
	if err := approval.VerifySubmission(signed, a.serverID, s.ClientID, ed25519.PublicKey(key), a.now().UTC()); err != nil {
		return approval.SignedRequest{}, err
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	digest := sha256.Sum256(encoded)
	var storedDigest, data []byte
	err = tx.QueryRowContext(ctx, "SELECT s.digest,r.envelope FROM authority_submissions s JOIN authority_requests r ON r.request_id=s.request_id WHERE s.client_id=? AND s.nonce=?", s.ClientID, s.Nonce).Scan(&storedDigest, &data)
	if err == nil {
		if string(storedDigest) != string(digest[:]) {
			return approval.SignedRequest{}, errors.New("submission nonce reused for different content")
		}
		var request approval.SignedRequest
		if err := json.Unmarshal(data, &request); err != nil {
			return approval.SignedRequest{}, err
		}
		if err := approval.VerifyRequest(request, a.serverID, a.key.Public().(ed25519.PublicKey)); err != nil {
			return approval.SignedRequest{}, err
		}
		return request, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return approval.SignedRequest{}, err
	}
	admittedOperation, stagedUploads, err := a.admitOperation(tx, s.ClientID, s.Operation)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	grant, grantErr := a.activeGrantForOperation(tx, s.ClientID, admittedOperation)
	authorized := grantErr == nil
	if grantErr != nil && !errors.Is(grantErr, sql.ErrNoRows) {
		return approval.SignedRequest{}, grantErr
	}
	request, err := approval.NewRequest(a.serverID, uuid.NewString(), s.ClientID, "", admittedOperation)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	envelope, err := approval.SignRequest(request, a.key)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	data, err = json.Marshal(envelope)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	status := "PENDING_APPROVAL"
	if authorized {
		status = "AUTHORIZED"
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO authority_requests(request_id,envelope,status) VALUES(?,?,?)", request.RequestID, data, status); err != nil {
		return approval.SignedRequest{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO authority_submissions(client_id,nonce,digest,request_id) VALUES(?,?,?,?)", s.ClientID, s.Nonce, digest[:], request.RequestID); err != nil {
		return approval.SignedRequest{}, err
	}
	if err := claimStagedUploads(tx, s.ClientID, request.RequestID, stagedUploads); err != nil {
		return approval.SignedRequest{}, err
	}
	if authorized {
		if _, err := tx.ExecContext(ctx, "INSERT INTO authority_grant_requests(request_id,grant_id) VALUES(?,?)", request.RequestID, grant.ID); err != nil {
			return approval.SignedRequest{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return approval.SignedRequest{}, err
	}
	return envelope, nil
}
