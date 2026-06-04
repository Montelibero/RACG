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
	if _, err := ruleFromScopePattern("docker stop nginx;rm /"); err == nil {
		t.Fatalf("expected inline separator pattern to be rejected")
	}
	if r, err := ruleFromScopePattern("docker stop n*"); err != nil {
		t.Fatalf("ruleFromScopePattern: %v", err)
	} else if strings.Join(r.Cmd.ArgvPrefix, "\x00") != "docker\x00stop\x00n*" {
		t.Fatalf("argv_prefix=%q", r.Cmd.ArgvPrefix)
	}
}
