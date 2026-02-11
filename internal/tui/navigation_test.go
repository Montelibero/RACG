package tui

import "testing"

func TestShowHistoryCallsRefresh(t *testing.T) {
	s := newUIState(nil, nil)
	called := 0
	s.historyRefresh = func() { called++ }

	s.showHistory(nil, nil)
	if s.page != "history" {
		t.Fatalf("page=%q, want history", s.page)
	}
	if called != 1 {
		t.Fatalf("refresh called %d times, want 1", called)
	}
}

func TestShowRulesCallsRefresh(t *testing.T) {
	s := newUIState(nil, nil)
	called := 0
	s.rulesRefresh = func() { called++ }

	s.showRules(nil, nil)
	if s.page != "rules" {
		t.Fatalf("page=%q, want rules", s.page)
	}
	if called != 1 {
		t.Fatalf("refresh called %d times, want 1", called)
	}
}

