package tui

import (
	"strings"
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

func TestBackDoesNotLeaveDashboard(t *testing.T) {
	s := newUIState(nil, nil)
	s.page = "dashboard"
	pages := tview.NewPages()
	pages.AddPage("pairing", tview.NewBox(), true, false)
	pages.AddPage("dashboard", tview.NewBox(), true, true)

	s.back(nil, pages)

	if s.page != "dashboard" {
		t.Fatalf("page=%q, want dashboard", s.page)
	}
	name, _ := pages.GetFrontPage()
	if name != "dashboard" {
		t.Fatalf("front=%q, want dashboard", name)
	}
}

func TestRenderMainTabsMarksActivePage(t *testing.T) {
	s := newUIState(nil, nil)
	s.page = "dashboard"
	got := s.renderMainTabs()

	for _, want := range []string{"[1 Pending]", "2 Jobs", "3 Rules", "4 History"} {
		if !strings.Contains(got, want) {
			t.Fatalf("tabs=%q want %q", got, want)
		}
	}

	s.page = "rules"
	got = s.renderMainTabs()
	if !strings.Contains(got, "[3 Rules]") {
		t.Fatalf("tabs=%q", got)
	}
}

func TestBackFromSecondaryPagesReturnsDashboard(t *testing.T) {
	for _, page := range []string{"rules", "history", "job"} {
		s := newUIState(nil, nil)
		s.page = page
		pages := tview.NewPages()
		pages.AddPage("dashboard", tview.NewBox(), true, false)
		pages.AddPage("rules", tview.NewBox(), true, page == "rules")
		pages.AddPage("history", tview.NewBox(), true, page == "history")
		pages.AddPage("job", tview.NewBox(), true, page == "job")

		s.back(nil, pages)

		if s.page != "dashboard" {
			t.Fatalf("from %q page=%q, want dashboard", page, s.page)
		}
		name, _ := pages.GetFrontPage()
		if name != "dashboard" {
			t.Fatalf("from %q front=%q, want dashboard", page, name)
		}
	}
}

func TestBackFromJobClosesHelpOverlay(t *testing.T) {
	s := newUIState(nil, nil)
	s.page = "job"
	pages := tview.NewPages()
	pages.AddPage("dashboard", tview.NewBox(), true, false)
	pages.AddPage("job", tview.NewBox(), true, true)
	pages.AddPage("help", tview.NewBox(), true, true)
	s.overlayClose = func() {
		pages.HidePage("help")
		s.overlayClose = nil
	}

	s.back(nil, pages)

	if s.overlayClose != nil {
		t.Fatal("overlayClose still set")
	}
	if s.page != "dashboard" {
		t.Fatalf("page=%q, want dashboard", s.page)
	}
	name, _ := pages.GetFrontPage()
	if name != "dashboard" {
		t.Fatalf("front=%q, want dashboard", name)
	}
}

func TestLeaveJobPageDoesNotRevealHiddenHelp(t *testing.T) {
	s := newUIState(nil, nil)
	s.page = "job"
	pages := tview.NewPages()
	pages.AddPage("dashboard", tview.NewBox(), true, false)
	pages.AddPage("help", tview.NewBox(), true, false)
	pages.AddAndSwitchToPage("job", tview.NewBox(), true)

	s.leaveJobPage(nil, pages, nil)

	if pageVisible(pages, "help") {
		t.Fatal("hidden help overlay became visible after leaving job")
	}
	name, _ := pages.GetFrontPage()
	if name != "dashboard" {
		t.Fatalf("front=%q, want dashboard", name)
	}
}

func TestOpenHelpSendsOverlayToFront(t *testing.T) {
	s := newUIState(nil, nil)
	pages := tview.NewPages()
	pages.AddPage("help", tview.NewBox(), true, false)
	pages.AddPage("dashboard", tview.NewBox(), true, true)
	pages.AddPage("job", tview.NewBox(), true, true)

	s.openHelp(nil, pages)

	name, _ := pages.GetFrontPage()
	if name != "help" {
		t.Fatalf("front=%q, want help", name)
	}

	s.closeOverlay(pages)
	name, _ = pages.GetFrontPage()
	if name == "help" {
		t.Fatalf("front=%q after close, want non-help page", name)
	}
}

func TestHelpTextUsesF1Only(t *testing.T) {
	got := helpText()
	if !strings.Contains(got, "F1 help") {
		t.Fatalf("helpText=%q, want F1 help hint", got)
	}
	for _, removed := range []string{"? help", "r rules", "h history"} {
		if strings.Contains(got, removed) {
			t.Fatalf("helpText=%q still contains removed shortcut %q", got, removed)
		}
	}
}
