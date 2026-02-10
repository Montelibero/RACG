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

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}
