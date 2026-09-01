package tui

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rivo/tview"
)

func TestServerUpdateStateChangesTabAndDetails(t *testing.T) {
	s := newUIState(nil, nil)
	s.activeMainTab = "pending"
	s.setServerUpdate(serverUpdateStatus{Phase: updateAvailable, Latest: "0.4.2"})
	if got := s.renderMainTabs(); !strings.Contains(got, "0 Server ↑") {
		t.Fatalf("tabs=%q", got)
	}
	if got := serverUpdateText("0.4.1", s.serverUpdateSnapshot()); !strings.Contains(got, "Update available: 0.4.1 -> 0.4.2") {
		t.Fatalf("details=%q", got)
	}

	s.setServerUpdate(serverUpdateStatus{Phase: updateInstalled, Latest: "0.4.2"})
	if got := s.renderMainTabs(); !strings.Contains(got, "0 Server ↻") {
		t.Fatalf("tabs=%q", got)
	}
	if got := serverUpdateText("0.4.1", s.serverUpdateSnapshot()); !strings.Contains(got, "restart required") {
		t.Fatalf("details=%q", got)
	}

	s.setServerUpdate(serverUpdateStatus{Phase: updateFailed, Latest: "0.4.2", Message: "permission denied"})
	if got := s.renderMainTabs(); !strings.Contains(got, "0 Server ↑") {
		t.Fatalf("failed update tabs=%q", got)
	}
}

func TestServerPageUsesItsOwnFocusChain(t *testing.T) {
	s := newUIState(nil, nil)
	serverFirst := tview.NewButton("first")
	serverSecond := tview.NewButton("second")
	s.serverFocus = []tview.Primitive{serverFirst, serverSecond}
	s.focus = []tview.Primitive{tview.NewInputField()}
	s.setCurrentPage("pairing")

	app := tview.NewApplication()
	app.SetFocus(serverFirst)
	s.cycleFocus(app)
	if app.GetFocus() != serverSecond {
		t.Fatalf("Tab left the Server focus chain")
	}
}

func TestCheckServerUpdateStopsAtContextDeadline(t *testing.T) {
	original := serverUpdateCommandContext
	serverUpdateCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "5")
	}
	defer func() { serverUpdateCommandContext = original }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	status := checkServerUpdate(ctx)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("offline update check blocked for %s", elapsed)
	}
	if status.Phase != updateUnavailable {
		t.Fatalf("status=%+v", status)
	}
}

func TestParseUpdateCheckOutput(t *testing.T) {
	got, err := parseUpdateCheckOutput("current_version: 0.4.1\nlatest_version: 0.4.2\nupdate_available: true\n")
	if err != nil || got.Latest != "0.4.2" || got.Phase != updateAvailable {
		t.Fatalf("status=%+v err=%v", got, err)
	}
}
