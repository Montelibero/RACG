// Package broker defines the narrow protocol through which an unprivileged
// broker can relay signed agent and approver messages to the authority.
//
// The authority connection deliberately exposes no execution, enrollment,
// revocation, rule or signing methods. A broker can deliver messages and read
// signed snapshots, but cannot authorize work by itself.
package broker

import (
	"encoding/json"

	"github.com/itolstov/racg/internal/approval"
)

const ProtocolVersion = 1

const (
	MethodSubmitAgent      = "v1/authority.submit-agent"
	MethodLookupSubmission = "v1/authority.lookup-submission"
	MethodSubmitDecision   = "v1/authority.submit-decision"
	MethodLookupDecision   = "v1/authority.lookup-decision"
)

type Request struct {
	Version int             `json:"version"`
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Version int             `json:"version"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// DecisionSubmission packages the only broker-controlled routing fields for a
// signed decision. The authority ignores broker assertions and verifies the
// decision against its own stored request before consuming it.
type DecisionSubmission struct {
	RequestID string                  `json:"request_id"`
	Decision  approval.SignedDecision `json:"decision"`
	Challenge []byte                  `json:"challenge"`
}
