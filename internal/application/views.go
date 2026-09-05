// Package application defines shared views and local interaction contracts.
package application

import "time"

// RequestSummary is a transport-independent summary for approval interfaces.
type RequestSummary struct {
	ID        string
	Status    string
	Summary   string
	Details   string
	SessionID string
	ClientID  string
	RiskFlags []string
	CreatedAt string
}

type ManualRuleInput struct {
	Source    string
	SessionID string
	OpType    string
	Match     string
	Pattern   string
}

type RuleSession struct {
	ID        string
	ClientID  string
	StartedAt time.Time
}

type RequestInfo struct {
	ID        string
	Status    string
	Summary   string
	Details   string
	SessionID string
	ClientID  string
	RiskFlags []string
	CreatedAt string

	Decision *DecisionRecord
	Result   *ResultRecord
}

type RuleScopeCandidate struct {
	OpType  string
	Segment string
	Pattern string
}

type DecisionRecord struct {
	Decision       string `json:"decision"`
	DecisionSource string `json:"decision_source"`
	DecidedAt      string `json:"decided_at"`
	RuleID         string `json:"rule_id,omitempty"`
}

type ResultRecord struct {
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	DurationMs      int64  `json:"duration_ms"`
	ExitCode        int    `json:"exit_code"`
	Status          string `json:"status"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	StdoutSHA256    string `json:"stdout_sha256"`
	StderrSHA256    string `json:"stderr_sha256"`
}
