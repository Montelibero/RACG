package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/httpapi"
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

	s.setActiveMainTab("jobs")
	got = s.renderMainTabs()
	for _, want := range []string{"1 Pending", "[2 Jobs]", "3 Rules", "4 History"} {
		if !strings.Contains(got, want) {
			t.Fatalf("tabs=%q want %q", got, want)
		}
	}
	if strings.Contains(got, "[1 Pending]") {
		t.Fatalf("tabs=%q still marks pending active", got)
	}

	s.page = "rules"
	s.setActiveMainTab("rules")
	got = s.renderMainTabs()
	if !strings.Contains(got, "[3 Rules]") {
		t.Fatalf("tabs=%q", got)
	}
}

func TestMainTabAtUsesRenderedTabPositions(t *testing.T) {
	tests := []struct {
		name string
		text string
		x    int
		want string
	}{
		{
			name: "active first tab bracket",
			text: "[1 Pending]   2 Jobs   3 Rules   4 History",
			x:    0,
			want: "pending",
		},
		{
			name: "inactive jobs after active pending",
			text: "[1 Pending]   2 Jobs   3 Rules   4 History",
			x:    strings.Index("[1 Pending]   2 Jobs   3 Rules   4 History", "2 Jobs"),
			want: "jobs",
		},
		{
			name: "active jobs starts earlier",
			text: "1 Pending   [2 Jobs]   3 Rules   4 History",
			x:    strings.Index("1 Pending   [2 Jobs]   3 Rules   4 History", "[2 Jobs]"),
			want: "jobs",
		},
		{
			name: "history",
			text: "1 Pending   2 Jobs   3 Rules   [4 History]",
			x:    strings.Index("1 Pending   2 Jobs   3 Rules   [4 History]", "4 History"),
			want: "history",
		},
		{
			name: "gap",
			text: "[1 Pending]   2 Jobs   3 Rules   4 History",
			x:    strings.Index("[1 Pending]   2 Jobs   3 Rules   4 History", "   "),
			want: "",
		},
	}
	for _, tt := range tests {
		if got := mainTabAt(tt.x, tt.text); got != tt.want {
			t.Fatalf("%s: mainTabAt=%q want %q", tt.name, got, tt.want)
		}
	}
}

func TestStatusBarDoesNotShowRootMode(t *testing.T) {
	s := newUIState(nil, nil)
	status := tview.NewTextView()

	s.refreshStatusBar(status)
	if got := status.GetText(false); got != "" {
		t.Fatalf("status without api=%q, want empty", got)
	}

	s.api = httpapi.New(config.Defaults())
	s.refreshStatusBar(status)
	got := status.GetText(false)
	if strings.Contains(got, "ROOT MODE") {
		t.Fatalf("status=%q still contains ROOT MODE", got)
	}
	for _, want := range []string{"F1 help", "pending=0", "running=0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("status=%q want %q", got, want)
		}
	}
}

func TestTerminalTitleShowsSpinnerWhenWorkIsActive(t *testing.T) {
	static := terminalTitle("0.2.5", 0, 0, 0)
	if static != "RACG v0.2.5" {
		t.Fatalf("static title=%q", static)
	}

	active1 := terminalTitle("0.2.5", 1, 0, 0)
	active2 := terminalTitle("0.2.5", 1, 0, 1)
	if active1 == active2 {
		t.Fatalf("active title did not spin: %q", active1)
	}
	for _, want := range []string{"RACG v0.2.5", "pending=1", "running=0"} {
		if !strings.Contains(active1, want) {
			t.Fatalf("active title=%q want %q", active1, want)
		}
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

func TestBackFromJobFocusesJobsList(t *testing.T) {
	app := tview.NewApplication()
	s := newUIState(httpapi.New(config.Defaults()), nil)
	s.page = "job"
	s.filter = tview.NewInputField()
	s.details = tview.NewTextView()
	s.pendingList = tview.NewList()
	s.jobsList = tview.NewList()
	pages := tview.NewPages()
	pages.AddPage("dashboard", tview.NewBox(), true, false)
	pages.AddAndSwitchToPage("job", tview.NewBox(), true)

	s.back(app, pages)

	if got := app.GetFocus(); got != s.jobsList {
		t.Fatalf("focus=%T, want jobsList", got)
	}
}

func TestGlobalTabDoesNotLeaveOverlay(t *testing.T) {
	app := tview.NewApplication()
	pages := tview.NewPages()
	s := newUIState(nil, nil)
	mainA := tview.NewInputField()
	mainB := tview.NewList()
	overlayInput := tview.NewInputField()
	s.focus = []tview.Primitive{mainA, mainB}
	app.SetFocus(overlayInput)
	s.overlayClose = func() {}

	ev := tcell.NewEventKey(tcell.KeyTAB, 0, tcell.ModNone)
	if got := s.handleGlobalInput(app, pages, ServeUIConfig{}, ev); got != ev {
		t.Fatalf("Tab should be passed to overlay, got %#v", got)
	}
	if got := app.GetFocus(); got != overlayInput {
		t.Fatalf("focus=%T, want overlay input", got)
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
