package application

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/itolstov/racg/internal/rules"
)

// LocalDecisionPlan describes a trusted interactive decision, not authority to
// execute. The caller must serialize the pending-state check, persist the
// decision, install rules in the originating session and dispatch at most once.
// Never accept this plan, or its inputs, as approval from a network broker.
type LocalDecisionPlan struct {
	Action string
	Status string
	Rules  []rules.Rule
}

// PlanLocalDecision preserves the standalone TUI's policy without HTTP,
// persistence, queue mutation, event publication or execution dependencies.
// ALLOW_ONCE and DENY deliberately ignore reusable-rule overrides.
func PlanLocalDecision(op rules.Op, flags []string, action string, overrides []rules.Rule, allowAlwaysForDangerous bool) (LocalDecisionPlan, error) {
	action = strings.TrimSpace(action)
	plan := LocalDecisionPlan{Action: action}
	switch action {
	case "DENY":
		plan.Status = "DENIED"
		return plan, nil
	case "ALLOW_ONCE":
		plan.Status = "APPROVED"
		return plan, nil
	case "ALLOW_SESSION", "ALLOW_ALWAYS":
		plan.Status = "APPROVED"
	default:
		return LocalDecisionPlan{}, errors.New("BAD_REQUEST")
	}
	if action == "ALLOW_ALWAYS" && !allowAlwaysForDangerous && IsDangerous(flags) {
		return LocalDecisionPlan{}, errors.New("ALLOW_ALWAYS_NOT_PERMITTED")
	}
	if len(overrides) > 0 {
		for _, rule := range overrides {
			// Own all mutable rule data; changing a UI input after review must not
			// silently alter the prepared rule.
			if rule.Cmd != nil {
				cmd := *rule.Cmd
				cmd.ArgvPrefix = append([]string(nil), cmd.ArgvPrefix...)
				rule.Cmd = &cmd
			}
			if rule.Path != nil {
				path := *rule.Path
				rule.Path = &path
			}
			if rule.ID == "" {
				rule.ID = uuid.NewString()
			}
			plan.Rules = append(plan.Rules, rule)
		}
	} else if rule, ok := RuleFromOpExact(uuid.NewString(), op); ok {
		plan.Rules = append(plan.Rules, rule)
	}
	if action == "ALLOW_ALWAYS" && !allowAlwaysForDangerous {
		for _, rule := range plan.Rules {
			if RuleMayMatchDangerousOperation(rule) {
				return LocalDecisionPlan{}, errors.New("ALLOW_ALWAYS_NOT_PERMITTED")
			}
		}
	}
	return plan, nil
}
