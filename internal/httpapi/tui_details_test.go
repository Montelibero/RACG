package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/rules"
)

func TestTUIDetailsForCmdRunShowsStructuredPreviewAndRiskHints(t *testing.T) {
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv":        []string{"bash", "-lc", "sudo kubectl delete secret app-secret"},
			"cwd":         "/repo",
			"timeout_sec": 45,
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := tuiDetails(requestRecord{Op: b})

	for _, want := range []string{
		"cwd: /repo",
		"timeout_sec: 45",
		"argv:",
		"  [0] bash",
		"  [1] -lc",
		"  [2] sudo kubectl delete secret app-secret",
		"review_hints: sudo, delete, secret",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestTUIDetailsShowsCommandAnalysisAllowBlock(t *testing.T) {
	api := New(config.Defaults())
	api.rules.AddAlways(rules.Rule{ID: "docker-stop-nginx", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"docker", "stop", "nginx"}}})
	api.rules.AddAlways(rules.Rule{ID: "echo", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"echo"}}})

	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-lc", "docker stop nginx && echo ok && rm /"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := api.tuiDetails(requestRecord{Op: b, SessionID: "sess1"})

	for _, want := range []string{
		"command_analysis:",
		"[green]ALLOW[-] docker stop nginx  matched=always:docker-stop-nginx",
		"[green]ALLOW[-] echo ok  matched=always:echo",
		"[red]BLOCK[-] rm /  reason=no matching rule",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestTUIDetailsEscapesCommandAnalysisBrackets(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-lc", `sed -E 's/[0-9]{8}/X/g' && grep -E 'app-(api|web)'`},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := api.tuiDetails(requestRecord{Op: b, SessionID: "sess1"})
	for _, want := range []string{"[0-9[]", "app-(api|web)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing escaped text %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "s/[0-9]{8}/X/g") {
		t.Fatalf("details contains raw dynamic-color tag text:\n%s", got)
	}
}

func TestTUIDetailsShowsUnsupportedSegmentSource(t *testing.T) {
	api := New(config.Defaults())

	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"sh", "-c", "echo redirect-test > /tmp/racg-scope-test.txt"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := api.tuiDetails(requestRecord{Op: b, SessionID: "sess1"})
	if strings.Contains(got, "BLOCK <unknown>") {
		t.Fatalf("details should not show unknown segment:\n%s", got)
	}
	for _, want := range []string{
		"[red]BLOCK[-] echo redirect-test >/tmp/racg-scope-test.txt  reason=redirect",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestRuleScopePatternRejectsShellSeparators(t *testing.T) {
	if _, err := ruleFromScopePattern("docker stop nginx && rm /"); err == nil {
		t.Fatalf("expected separator pattern to be rejected")
	}
	if r, err := ruleFromScopePattern("docker stop n*"); err != nil {
		t.Fatalf("ruleFromScopePattern: %v", err)
	} else if strings.Join(r.Cmd.ArgvPrefix, "\x00") != "docker\x00stop\x00n*" {
		t.Fatalf("argv_prefix=%q", r.Cmd.ArgvPrefix)
	}
}

func TestRuleScopePatternAllowsRegexPipeInsideArg(t *testing.T) {
	r, err := ruleFromScopePattern(`grep -E pavuuk-(main-bot|web-admin|user-runtime)`)
	if err != nil {
		t.Fatalf("ruleFromScopePattern: %v", err)
	}
	if got := strings.Join(r.Cmd.ArgvPrefix, "\x00"); got != "grep\x00-E\x00pavuuk-(main-bot|web-admin|user-runtime)" {
		t.Fatalf("argv_prefix=%q", r.Cmd.ArgvPrefix)
	}
}

func TestRuleScopeCandidatesIncludeEachShellSegment(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-lc", "echo second-chain && uname -s && printf done\\n"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1"}

	got := api.RuleScopeCandidatesForTUI("req1")
	if len(got) != 3 {
		t.Fatalf("candidates=%d want 3: %#v", len(got), got)
	}
	want := []string{"echo second-chain", "uname -s", "printf done\\n"}
	for i := range want {
		if got[i].Pattern != want[i] || got[i].Segment != want[i] {
			t.Fatalf("candidate %d=%#v want %q", i, got[i], want[i])
		}
	}
}

func TestRuleScopeCandidatesIncludePathOps(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "fs.read",
		"payload": map[string]any{
			"path": "/apps/haproxy/haproxy.cfg",
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1", ClientID: "cli"}

	got := api.RuleScopeCandidatesForTUI("req1")
	if len(got) != 1 {
		t.Fatalf("candidates=%d want 1: %#v", len(got), got)
	}
	if got[0].OpType != "fs.read" || got[0].Segment != "/apps/haproxy/haproxy.cfg" || got[0].Pattern != "/apps/haproxy/haproxy.cfg" {
		t.Fatalf("candidate=%#v", got[0])
	}
}

func TestDecideWithRulePatternsForTUISavesPathRule(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "fs.read",
		"payload": map[string]any{
			"path": "/apps/haproxy/haproxy.cfg",
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1", ClientID: "cli"}

	err = api.DecideWithRulePatternsForTUI("req1", "ALLOW_SESSION", []string{"/apps/haproxy/haproxy.cfg"})
	if err != nil {
		t.Fatalf("DecideWithRulePatternsForTUI: %v", err)
	}

	rows := api.ListSessionRulesForTUI()
	if len(rows) != 1 {
		t.Fatalf("session rules=%d want 1: %#v", len(rows), rows)
	}
	if rows[0].OpType != "fs.read" {
		t.Fatalf("op_type=%q", rows[0].OpType)
	}
	if rows[0].PathExact == nil || *rows[0].PathExact != "/apps/haproxy/haproxy.cfg" {
		t.Fatalf("path_exact=%v", rows[0].PathExact)
	}
}

func TestDecideWithRulePatternsForTUISavesEachSessionRule(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-lc", "echo second-chain && uname -s && printf done\\n"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1", ClientID: "cli"}

	err = api.DecideWithRulePatternsForTUI("req1", "ALLOW_SESSION", []string{"echo second-chain", "uname -s", "printf done\\n"})
	if err != nil {
		t.Fatalf("DecideWithRulePatternsForTUI: %v", err)
	}

	rows := api.ListSessionRulesForTUI()
	if len(rows) != 3 {
		t.Fatalf("session rules=%d want 3: %#v", len(rows), rows)
	}
	got := map[string]bool{}
	for _, row := range rows {
		if row.CmdArgvJSON != nil {
			got[*row.CmdArgvJSON] = true
		}
	}
	for _, want := range []string{`["echo","second-chain"]`, `["uname","-s"]`, `["printf","done\\n"]`} {
		if !got[want] {
			t.Fatalf("missing rule %s in %#v", want, got)
		}
	}
}
