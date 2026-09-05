package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/events"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

// approveByRule is a trusted local policy path, not a broker approval API.
// It takes identity and operation from the stored request, serializes with
// TUI decisions and persists before making an approval visible.
func (a *API) approveByRule(ctx context.Context, id string) (string, error) {
	a.reqsMu.Lock()
	rec, ok := a.reqs[id]
	if !ok {
		a.reqsMu.Unlock()
		return "", errors.New("REQUEST_NOT_FOUND")
	}
	if rec.Status != "PENDING_APPROVAL" {
		a.reqsMu.Unlock()
		return rec.Status, nil
	}
	var op rules.Op
	if err := json.Unmarshal(rec.Op, &op); err != nil {
		a.reqsMu.Unlock()
		return rec.Status, err
	}
	match, allowed := a.rules.Match(rec.SessionID, op)
	if !allowed {
		a.reqsMu.Unlock()
		return rec.Status, nil
	}
	now := time.Now().UTC()
	if a.st != nil {
		if err := a.st.CommitPendingDecision(ctx, store.Decision{
			RequestID: id, Decision: "ALLOW_RULE", DecisionSource: "rule",
			DecidedAt: now, RuleID: match.RuleID,
		}, nil); err != nil {
			a.reqsMu.Unlock()
			return rec.Status, err
		}
	}
	rec.Status = "APPROVED"
	rec.Decision = &decisionRecord{Decision: "ALLOW_RULE", DecisionSource: "rule", DecidedAt: now.Format(time.RFC3339Nano), RuleID: match.RuleID}
	a.reqs[id] = rec
	a.reqsMu.Unlock()
	a.hub.Publish(events.Event{
		Type: "request.decision", RequestID: id, SessionID: rec.SessionID, ClientID: rec.ClientID,
		Data: map[string]any{"decision": "ALLOW_RULE", "decision_source": "rule", "rule_id": match.RuleID, "status": "APPROVED"},
	})
	go a.executeApprovedRequest(id, auth.Claims{SessionID: rec.SessionID, ClientID: rec.ClientID}, op)
	return "APPROVED", nil
}
