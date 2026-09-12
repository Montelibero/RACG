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

// LookupDecision is read-only recovery for a lost decision receipt. It
// authenticates the current approver key, returns an authority-signed snapshot
// and never creates, approves, cancels, claims or reruns a request.
func (a *Authority) LookupDecision(ctx context.Context, signed approval.SignedDecisionLookup) (approval.SignedDecisionLookupResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	q := signed.Lookup
	var key []byte
	var revoked int
	if err := a.db.QueryRowContext(ctx, "SELECT public_key,revoked FROM authority_devices WHERE device_id=?", q.DeviceID).Scan(&key, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return approval.SignedDecisionLookupResult{}, fmt.Errorf("device is not enrolled: %w", err)
		}
		return approval.SignedDecisionLookupResult{}, err
	}
	if revoked != 0 {
		return approval.SignedDecisionLookupResult{}, errors.New("device revoked")
	}
	if err := approval.VerifyDecisionLookupCredentials(signed, a.serverID, q.DeviceID, ed25519.PublicKey(key), a.now().UTC()); err != nil {
		return approval.SignedDecisionLookupResult{}, err
	}
	var envelope, decisionData []byte
	var status string
	err := a.db.QueryRowContext(ctx, "SELECT envelope,status,signed_decision FROM authority_requests WHERE request_id=?", q.RequestID).Scan(&envelope, &status, &decisionData)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.SignDecisionLookupResult(q, nil, "", "", "", a.key)
	}
	if err != nil {
		return approval.SignedDecisionLookupResult{}, err
	}
	var request approval.SignedRequest
	if err := json.Unmarshal(envelope, &request); err != nil {
		return approval.SignedDecisionLookupResult{}, err
	}
	if err := approval.VerifyRequest(request, a.serverID, a.key.Public().(ed25519.PublicKey)); err != nil {
		return approval.SignedDecisionLookupResult{}, err
	}
	if err := approval.VerifyDecisionLookup(signed, a.serverID, q.DeviceID, request.Request, ed25519.PublicKey(key), a.now().UTC()); err != nil {
		return approval.SignedDecisionLookupResult{}, err
	}
	var action, decisionDevice string
	if len(decisionData) != 0 {
		var decision approval.SignedDecision
		if err := json.Unmarshal(decisionData, &decision); err != nil {
			return approval.SignedDecisionLookupResult{}, err
		}
		action = decision.Decision.Action
		decisionDevice = decision.Decision.DeviceID
		if action == "" || decisionDevice == "" {
			return approval.SignedDecisionLookupResult{}, errors.New("stored decision identity incomplete")
		}
	}
	return approval.SignDecisionLookupResult(q, &request, status, action, decisionDevice, a.key)
}
