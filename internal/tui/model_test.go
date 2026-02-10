package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

type fakeApprover struct {
	pending []Request
	decided []string
}

func (f *fakeApprover) ListPending() ([]Request, error) {
	return f.pending, nil
}

func (f *fakeApprover) Decide(id string, decision Decision) error {
	f.decided = append(f.decided, id+":"+string(decision))
	return nil
}

func TestModelDeny(t *testing.T) {
	ap := &fakeApprover{pending: []Request{{ID: "r1", Summary: "cmd.run /bin/echo hi"}}}
	m := NewModel(ap, "CODE12")

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	mm := m2.(Model)

	if len(ap.decided) != 1 {
		t.Fatalf("decided=%v", ap.decided)
	}
	if ap.decided[0] != "r1:DENY" {
		t.Fatalf("decided[0]=%q", ap.decided[0])
	}
	if mm.status != "DENIED r1" {
		t.Fatalf("status=%q", mm.status)
	}
}
