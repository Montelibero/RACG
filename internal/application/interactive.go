package application

import (
	"context"
	"time"

	"github.com/itolstov/racg/internal/events"
	"github.com/itolstov/racg/internal/store"
)

// InteractiveBackend is the trusted in-process UI contract. Legacy method names
// remain during extraction. It must not be exposed as an unsigned remote service.
type InteractiveBackend interface {
	PairingCode() string
	PairingExpiresIn() time.Duration
	RegeneratePairingCode()
	SubscribeEvents(int) (<-chan events.Event, func())
	GetLiveJobOutput(string) (string, bool)
	ListPendingForTUI() []RequestSummary
	ListRunningForTUI() []RequestSummary
	ListJobsForTUI(bool) []RequestSummary
	GetRequestInfoForTUI(string) (RequestInfo, bool)
	DecideForTUI(string, string) error
	DecideWithRulePatternsForTUI(string, string, []string) error
	RuleScopeAnalysisForTUI(string) ([]RuleScopeCandidate, string)
	KillForTUI(string) error
	ListSessionRulesForTUI() []store.RuleRow
	AddManualRuleForTUI(ManualRuleInput) (string, error)
	ListManualRuleSessionsForTUI() ([]RuleSession, error)
	SetAlwaysRuleEnabledForTUI(string, bool) error
	DeleteRuleForTUI(string, string) error
}

// HistoryReader lets an interface read history without owning a database handle.
type HistoryReader interface {
	ListRules(context.Context, int) ([]store.RuleRow, error)
	ListSessions(context.Context, int) ([]store.Session, error)
	ListSessionHistoryItems(context.Context, string, int) ([]store.SessionHistoryItem, error)
}
