package rules

import (
	"encoding/json"
	"testing"
)

func TestMatchCmdRunArgvPrefix(t *testing.T) {
	e := NewEngine()
	e.AddAlways(Rule{
		ID:     "r1",
		OpType: "cmd.run",
		Cmd: &CmdRule{
			ArgvPrefix: []string{"/bin/echo", "hi"},
		},
	})

	op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{"argv": []string{"/bin/echo", "hi", "there"}})}
	m, ok := e.Match("sess1", op)
	if !ok {
		t.Fatalf("expected match")
	}
	if m.RuleID != "r1" {
		t.Fatalf("RuleID=%q", m.RuleID)
	}
	if m.Source != "always" {
		t.Fatalf("Source=%q", m.Source)
	}
}

func TestCmdRuleMatchesAnyStdinContent(t *testing.T) {
	e := NewEngine()
	e.AddAlways(Rule{ID: "argv-only", OpType: "cmd.run", Cmd: &CmdRule{ArgvPrefix: []string{"/bin/bash", "-s"}}})

	first := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"/bin/bash", "-s"}, "stdin_sha256": "abc123",
	})}
	match, ok := e.Match("sess", first)
	if !ok || match.RuleID != "argv-only" {
		t.Fatalf("first stdin match=%+v ok=%t", match, ok)
	}

	changed := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"/bin/bash", "-s"}, "stdin_sha256": "different",
	})}
	match, ok = e.Match("sess", changed)
	if !ok || match.RuleID != "argv-only" {
		t.Fatalf("changed stdin match=%+v ok=%t", match, ok)
	}

	withoutStdin := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"/bin/bash", "-s"},
	})}
	match, ok = e.Match("sess", withoutStdin)
	if !ok || match.RuleID != "argv-only" {
		t.Fatalf("plain command match=%+v ok=%t", match, ok)
	}
}

func TestExactShellArgvRuleMatchesAnyStdinContent(t *testing.T) {
	e := NewEngine()
	e.AddSession("sess", Rule{ID: "exact-shell", OpType: "cmd.run", Cmd: &CmdRule{
		ArgvPrefix: []string{"/bin/bash", "-c", "cat"},
	}})

	for _, hash := range []string{"abc123", "different"} {
		op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
			"argv": []string{"/bin/bash", "-c", "cat"}, "stdin_sha256": hash,
		})}
		match, ok := e.Match("sess", op)
		if !ok || match.RuleID != "exact-shell" {
			t.Fatalf("hash=%q match=%+v ok=%t", hash, match, ok)
		}
	}

	changedScript := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"/bin/bash", "-c", "rm /"}, "stdin_sha256": "abc123",
	})}
	if _, ok := e.Match("sess", changedScript); ok {
		t.Fatal("exact shell argv rule matched changed script")
	}
}

func TestMatchCmdRunArgvPrefixWithGlobArg(t *testing.T) {
	e := NewEngine()
	e.AddAlways(Rule{
		ID:     "curl-health",
		OpType: "cmd.run",
		Cmd: &CmdRule{
			ArgvPrefix: []string{"curl", "*health*"},
		},
	})

	op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{"argv": []string{"curl", "https://example.test/healthz"}})}
	m, ok := e.Match("sess1", op)
	if !ok {
		t.Fatalf("expected match")
	}
	if m.RuleID != "curl-health" {
		t.Fatalf("RuleID=%q", m.RuleID)
	}
}

func TestMatchCmdRunShellRequiresEverySegmentAllowed(t *testing.T) {
	e := NewEngine()
	e.AddAlways(Rule{ID: "docker-stop-nginx", OpType: "cmd.run", Cmd: &CmdRule{ArgvPrefix: []string{"docker", "stop", "nginx"}}})
	e.AddAlways(Rule{ID: "echo", OpType: "cmd.run", Cmd: &CmdRule{ArgvPrefix: []string{"echo"}}})

	allowed := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"bash", "-lc", "docker stop nginx && echo ok"},
	})}
	if _, ok := e.Match("sess1", allowed); !ok {
		t.Fatalf("expected shell command to match because every segment is allowed")
	}

	blocked := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"bash", "-lc", "docker stop nginx && echo ok && rm /"},
	})}
	if _, ok := e.Match("sess1", blocked); ok {
		t.Fatalf("unexpected match when one shell segment is not allowed")
	}
}

func TestMatchCmdRunShellDoesNotAllowByShellBinaryRule(t *testing.T) {
	e := NewEngine()
	e.AddAlways(Rule{ID: "bash", OpType: "cmd.run", Cmd: &CmdRule{ArgvPrefix: []string{"bash"}}})

	op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"bash", "-lc", "rm /"},
	})}
	if _, ok := e.Match("sess1", op); ok {
		t.Fatalf("shell binary rule must not allow unchecked inner command")
	}
}

func TestMatchCmdRunRuleCanAllowGlobArgWithAnyTail(t *testing.T) {
	e := NewEngine()
	e.AddAlways(Rule{ID: "docker-stop-n", OpType: "cmd.run", Cmd: &CmdRule{ArgvPrefix: []string{"docker", "stop", "n*"}, TailAny: true}})

	op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"docker", "stop", "nginx", "--time", "10"},
	})}
	if _, ok := e.Match("sess1", op); !ok {
		t.Fatalf("expected glob arg with any tail to match")
	}
}

func TestExplainCmdRunShellMarksAllowedAndBlockedSegments(t *testing.T) {
	e := NewEngine()
	e.AddAlways(Rule{ID: "docker-stop-nginx", OpType: "cmd.run", Cmd: &CmdRule{ArgvPrefix: []string{"docker", "stop", "nginx"}}})
	e.AddAlways(Rule{ID: "echo", OpType: "cmd.run", Cmd: &CmdRule{ArgvPrefix: []string{"echo"}}})

	op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"bash", "-lc", "docker stop nginx && echo ok && rm /"},
	})}
	explain := e.Explain("sess1", op)

	if explain.Allowed {
		t.Fatalf("explain allowed unexpectedly: %#v", explain)
	}
	if len(explain.Segments) != 3 {
		t.Fatalf("segments=%d want 3", len(explain.Segments))
	}
	if !explain.Segments[0].Allowed || explain.Segments[0].RuleID != "docker-stop-nginx" {
		t.Fatalf("segment 0=%#v", explain.Segments[0])
	}
	if !explain.Segments[1].Allowed || explain.Segments[1].RuleID != "echo" {
		t.Fatalf("segment 1=%#v", explain.Segments[1])
	}
	if explain.Segments[2].Allowed || explain.Segments[2].Reason != "no matching rule" {
		t.Fatalf("segment 2=%#v", explain.Segments[2])
	}
}

func TestMatchPathPrefix(t *testing.T) {
	e := NewEngine()
	e.AddSession("sess1", Rule{ID: "s1", OpType: "fs.read", Path: &PathRule{Prefix: "/home/itolstov/"}})

	op := Op{Type: "fs.read", Payload: mustJSON(t, map[string]any{"path": "/home/itolstov/.bashrc"})}
	m, ok := e.Match("sess1", op)
	if !ok {
		t.Fatalf("expected match")
	}
	if m.RuleID != "s1" {
		t.Fatalf("RuleID=%q", m.RuleID)
	}
	if m.Source != "session" {
		t.Fatalf("Source=%q", m.Source)
	}
}

func TestNoMatchDifferentSession(t *testing.T) {
	e := NewEngine()
	e.AddSession("sess1", Rule{ID: "s1", OpType: "fs.read", Path: &PathRule{Prefix: "/home/"}})

	op := Op{Type: "fs.read", Payload: mustJSON(t, map[string]any{"path": "/home/x"})}
	if _, ok := e.Match("sess2", op); ok {
		t.Fatalf("unexpected match")
	}
}

func TestSessionRulesSnapshotCopiesRules(t *testing.T) {
	e := NewEngine()
	e.AddSession("sess1", Rule{ID: "s1", OpType: "cmd.run", Cmd: &CmdRule{ArgvPrefix: []string{"git", "status"}}})

	snap := e.SessionRulesSnapshot()
	snap["sess1"][0].ID = "changed"

	snap2 := e.SessionRulesSnapshot()
	if snap2["sess1"][0].ID != "s1" {
		t.Fatalf("snapshot mutated engine rule id=%q", snap2["sess1"][0].ID)
	}
}

func TestFileTransferPathRules(t *testing.T) {
	e := NewEngine()
	e.AddSession("sess", Rule{ID: "upload", OpType: "fs.upload", Path: &PathRule{Exact: "/srv/upload.bin"}})
	e.AddAlways(Rule{ID: "download", OpType: "fs.download", Path: &PathRule{Prefix: "/srv/exports/"}})
	tests := []struct {
		op      Op
		allowed bool
	}{
		{Op{Type: "fs.upload", Payload: mustJSON(t, map[string]any{"path": "/srv/upload.bin"})}, true},
		{Op{Type: "fs.upload", Payload: mustJSON(t, map[string]any{"path": "/srv/other.bin"})}, false},
		{Op{Type: "fs.download", Payload: mustJSON(t, map[string]any{"path": "/srv/exports/data.bin"})}, true},
		{Op{Type: "fs.download", Payload: mustJSON(t, map[string]any{"path": "/etc/shadow"})}, false},
	}
	for _, tt := range tests {
		if _, got := e.Match("sess", tt.op); got != tt.allowed {
			t.Fatalf("op=%s payload=%s allowed=%t want=%t", tt.op.Type, tt.op.Payload, got, tt.allowed)
		}
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}
