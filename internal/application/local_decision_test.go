package application

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/itolstov/racg/internal/rules"
)

func TestLocalDecisionPolicy(t *testing.T) {
	op := rules.Op{Type: "cmd.run", Payload: json.RawMessage(`{"argv":["/bin/echo","hello"]}`)}
	dangerousRule := rules.Rule{OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"bash", "-lc", "*"}}}
	for _, tc := range []struct {
		name, action, status, errorCode string
		flags                           []string
		overrides                       []rules.Rule
		allowDangerous                  bool
		ruleCount                       int
	}{
		{name: "deny", action: "DENY", status: "DENIED"},
		{name: "once", action: "ALLOW_ONCE", status: "APPROVED"},
		{name: "session", action: "ALLOW_SESSION", status: "APPROVED", ruleCount: 1},
		{name: "always", action: "ALLOW_ALWAYS", status: "APPROVED", ruleCount: 1},
		{name: "trim", action: " ALLOW_ONCE ", status: "APPROVED"},
		{name: "empty", errorCode: "BAD_REQUEST"},
		{name: "unknown", action: "ALLOW_UNTIL", errorCode: "BAD_REQUEST"},
		{name: "case sensitive", action: "allow_once", errorCode: "BAD_REQUEST"},
		{name: "deny ignores scope", action: "DENY", status: "DENIED", overrides: []rules.Rule{dangerousRule}},
		{name: "once ignores scope", action: "ALLOW_ONCE", status: "APPROVED", overrides: []rules.Rule{dangerousRule}},
		{name: "dangerous once", action: "ALLOW_ONCE", status: "APPROVED", flags: []string{"DESTRUCTIVE_FS"}},
		{name: "dangerous session", action: "ALLOW_SESSION", status: "APPROVED", flags: []string{"DESTRUCTIVE_FS"}, ruleCount: 1},
		{name: "dangerous always", action: "ALLOW_ALWAYS", flags: []string{"DESTRUCTIVE_FS"}, errorCode: "ALLOW_ALWAYS_NOT_PERMITTED"},
		{name: "broad always", action: "ALLOW_ALWAYS", overrides: []rules.Rule{dangerousRule}, errorCode: "ALLOW_ALWAYS_NOT_PERMITTED"},
		{name: "broad session", action: "ALLOW_SESSION", status: "APPROVED", overrides: []rules.Rule{dangerousRule}, ruleCount: 1},
		{name: "explicit dangerous policy", action: "ALLOW_ALWAYS", status: "APPROVED", flags: []string{"DESTRUCTIVE_FS"}, overrides: []rules.Rule{dangerousRule}, allowDangerous: true, ruleCount: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlanLocalDecision(op, tc.flags, tc.action, tc.overrides, tc.allowDangerous)
			if tc.errorCode != "" {
				if err == nil || err.Error() != tc.errorCode {
					t.Fatalf("error=%v want=%s", err, tc.errorCode)
				}
				if !reflect.DeepEqual(got, LocalDecisionPlan{}) {
					t.Fatalf("failed plan leaked rules: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.status || len(got.Rules) != tc.ruleCount {
				t.Fatalf("plan=%+v", got)
			}
			for _, rule := range got.Rules {
				if rule.ID == "" {
					t.Fatal("missing rule ID")
				}
			}
		})
	}
}

func TestLocalDecisionOwnsOverrides(t *testing.T) {
	input := []rules.Rule{
		{ID: "existing", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo", "hello"}, TailAny: true}},
		{OpType: "fs.read", Path: &rules.PathRule{Glob: "/var/log/*"}},
	}
	plan, err := PlanLocalDecision(rules.Op{}, nil, "ALLOW_SESSION", input, false)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Cmd.ArgvPrefix[0] = "/bin/rm"
	input[0].Cmd.TailAny = false
	input[1].Path.Glob = "/*"
	if plan.Rules[0].ID != "existing" || plan.Rules[0].Cmd.ArgvPrefix[0] != "/bin/echo" || !plan.Rules[0].Cmd.TailAny || plan.Rules[1].Path.Glob != "/var/log/*" {
		t.Fatalf("caller mutation changed plan: %+v", plan)
	}
	if input[1].ID != "" {
		t.Fatal("assigned ID mutated input")
	}
}

func TestLocalDecisionExactRules(t *testing.T) {
	for _, kind := range []string{"fs.read", "fs.download", "fs.patch_unified", "fs.upload", "conf.set"} {
		t.Run(kind, func(t *testing.T) {
			plan, err := PlanLocalDecision(rules.Op{Type: kind, Payload: json.RawMessage(`{"path":"/srv/data"}`)}, nil, "ALLOW_SESSION", nil, false)
			if err != nil || len(plan.Rules) != 1 {
				t.Fatalf("plan=%+v err=%v", plan, err)
			}
			if plan.Rules[0].OpType != kind || plan.Rules[0].Path.Exact != "/srv/data" {
				t.Fatalf("rule=%+v", plan.Rules[0])
			}
		})
	}
	for _, op := range []rules.Op{
		{Type: "unknown"},
		{Type: "cmd.run", Payload: json.RawMessage(`{}`)},
		{Type: "fs.read", Payload: json.RawMessage(`{}`)},
	} {
		plan, err := PlanLocalDecision(op, nil, "ALLOW_SESSION", nil, false)
		if err != nil || len(plan.Rules) != 0 || plan.Status != "APPROVED" {
			t.Fatalf("legacy no-rule behavior changed: %+v %v", plan, err)
		}
	}
}
