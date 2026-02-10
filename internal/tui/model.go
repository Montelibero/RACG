package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

type Decision string

const (
	DecisionAllowOnce    Decision = "ALLOW_ONCE"
	DecisionAllowSession Decision = "ALLOW_SESSION"
	DecisionAllowAlways  Decision = "ALLOW_ALWAYS"
	DecisionDeny         Decision = "DENY"
)

type Request struct {
	ID      string
	Summary string
}

type Approver interface {
	ListPending() ([]Request, error)
	Decide(id string, decision Decision) error
}

type Model struct {
	ap          Approver
	pairingCode string

	pending []Request
	cursor  int
	status  string
}

func NewModel(ap Approver, pairingCode string) Model {
	pending, _ := ap.ListPending()
	return Model{ap: ap, pairingCode: pairingCode, pending: pending}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "j", "down":
			if m.cursor < len(m.pending)-1 {
				m.cursor++
			}
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "r":
			p, err := m.ap.ListPending()
			if err != nil {
				m.status = "refresh error: " + err.Error()
				return m, nil
			}
			m.pending = p
			if m.cursor >= len(m.pending) {
				m.cursor = max(0, len(m.pending)-1)
			}
			m.status = fmt.Sprintf("refreshed (%d)", len(m.pending))
		case "a":
			return m.decideSelected(DecisionAllowOnce)
		case "s":
			return m.decideSelected(DecisionAllowSession)
		case "w":
			return m.decideSelected(DecisionAllowAlways)
		case "d":
			return m.decideSelected(DecisionDeny)
		}
	}
	return m, nil
}

func (m Model) decideSelected(dec Decision) (tea.Model, tea.Cmd) {
	if len(m.pending) == 0 {
		m.status = "no pending"
		return m, nil
	}
	r := m.pending[m.cursor]
	if err := m.ap.Decide(r.ID, dec); err != nil {
		m.status = "decision error: " + err.Error()
		return m, nil
	}

	// Remove from list.
	m.pending = append(m.pending[:m.cursor], m.pending[m.cursor+1:]...)
	if m.cursor >= len(m.pending) {
		m.cursor = max(0, len(m.pending)-1)
	}

	switch dec {
	case DecisionDeny:
		m.status = "DENIED " + r.ID
	default:
		m.status = "APPROVED " + r.ID
	}
	return m, nil
}

func (m Model) View() string {
	head := fmt.Sprintf("RACG approvals (pairing_code=%s)\n\n", m.pairingCode)
	if len(m.pending) == 0 {
		return head + "No pending requests. (r=refresh, q=quit)\n\n" + m.status + "\n"
	}

	out := head
	for i, r := range m.pending {
		cur := " "
		if i == m.cursor {
			cur = ">"
		}
		out += fmt.Sprintf("%s %s\n", cur, r.Summary)
	}
	out += "\nkeys: a=allow once, s=allow session, w=allow always, d=deny, r=refresh, q=quit\n"
	if m.status != "" {
		out += "\n" + m.status + "\n"
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
