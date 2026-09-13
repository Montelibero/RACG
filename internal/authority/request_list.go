package authority

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/itolstov/racg/internal/approval"
)

// ListPending is read-only recovery for the approval queue. It authenticates
// the current approver device and never creates, consumes or executes a request.
func (a *Authority) ListPending(ctx context.Context, signed approval.SignedRequestList) (approval.SignedRequestListResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	list := signed.List
	var key []byte
	var revoked int
	if err := a.db.QueryRowContext(ctx, "SELECT public_key,revoked FROM authority_devices WHERE device_id=?", list.DeviceID).Scan(&key, &revoked); err != nil {
		return approval.SignedRequestListResult{}, fmt.Errorf("device is not enrolled: %w", err)
	}
	if revoked != 0 {
		return approval.SignedRequestListResult{}, errors.New("device revoked")
	}
	if err := approval.VerifyRequestList(signed, a.serverID, list.DeviceID, ed25519.PublicKey(key), a.now().UTC()); err != nil {
		return approval.SignedRequestListResult{}, err
	}
	rows, err := a.db.QueryContext(ctx,
		"SELECT envelope FROM authority_requests WHERE status='PENDING_APPROVAL' ORDER BY request_id")
	if err != nil {
		return approval.SignedRequestListResult{}, err
	}
	defer rows.Close()
	requests := []approval.SignedRequest{}
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return approval.SignedRequestListResult{}, err
		}
		var request approval.SignedRequest
		if err := json.Unmarshal(data, &request); err != nil {
			return approval.SignedRequestListResult{}, err
		}
		if err := approval.VerifyRequest(request, a.serverID, a.key.Public().(ed25519.PublicKey)); err != nil {
			return approval.SignedRequestListResult{}, err
		}
		requests = append(requests, request)
	}
	if err := rows.Err(); err != nil {
		return approval.SignedRequestListResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return approval.SignedRequestListResult{}, err
	}
	return approval.SignRequestListResult(list, requests, a.key)
}
