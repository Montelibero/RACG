package cli

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

func TestReadonlyDiagnosticsPresetRulesMatchOnlyReadOnlyPrefixes(t *testing.T) {
	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	installed, skipped, err := installRulePreset(context.Background(), st, "readonly-diagnostics")
	if err != nil {
		t.Fatalf("installRulePreset: %v", err)
	}
	if installed != 6 || skipped != 0 {
		t.Fatalf("installed=%d skipped=%d", installed, skipped)
	}

	rs, err := st.LoadEnabledAlwaysRules(context.Background())
	if err != nil {
		t.Fatalf("LoadEnabledAlwaysRules: %v", err)
	}
	engine := rules.NewEngine()
	for _, r := range rs {
		engine.AddAlways(r)
	}

	if _, ok := engine.Match("sess", cmdRunOp(t, []string{"git", "status", "--short"})); !ok {
		t.Fatalf("git status did not match")
	}
	if _, ok := engine.Match("sess", cmdRunOp(t, []string{"kubectl", "logs", "deploy/app"})); !ok {
		t.Fatalf("kubectl logs did not match")
	}
	if _, ok := engine.Match("sess", cmdRunOp(t, []string{"curl", "https://example.test/healthz"})); !ok {
		t.Fatalf("curl health did not match")
	}
	if _, ok := engine.Match("sess", cmdRunOp(t, []string{"git", "push"})); ok {
		t.Fatalf("git push unexpectedly matched")
	}
	if _, ok := engine.Match("sess", cmdRunOp(t, []string{"kubectl", "delete", "pod", "x"})); ok {
		t.Fatalf("kubectl delete unexpectedly matched")
	}
}

func cmdRunOp(t *testing.T, argv []string) rules.Op {
	t.Helper()
	b, err := json.Marshal(map[string]any{"argv": argv})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return rules.Op{Type: "cmd.run", Payload: b}
}
