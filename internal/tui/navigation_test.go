package tui

import (
	"testing"

	"github.com/rivo/tview"
)

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

func TestMaybeAutoSwitchToDashboardFromPairing(t *testing.T) {
	s := newUIState(nil, nil)
	s.page = "pairing"

	if switched := s.maybeAutoSwitchToDashboard(nil, nil, 1); !switched {
		t.Fatalf("expected switch=true")
	}
	if s.page != "dashboard" {
		t.Fatalf("page=%q, want dashboard", s.page)
	}
}

func TestSwitchMainPageHidesPrevious(t *testing.T) {
	s := newUIState(nil, nil)
	pages := tview.NewPages()
	pages.AddPage("pairing", tview.NewBox(), true, true)
	pages.AddPage("dashboard", tview.NewBox(), true, false)
	pages.AddPage("rules", tview.NewBox(), true, false)
	pages.AddPage("history", tview.NewBox(), true, false)

	s.switchMainPage(pages, "history")
	name, _ := pages.GetFrontPage()
	if name != "history" {
		t.Fatalf("front=%q, want history", name)
	}

	s.switchMainPage(pages, "dashboard")
	name, _ = pages.GetFrontPage()
	if name != "dashboard" {
		t.Fatalf("front=%q, want dashboard", name)
	}
}
