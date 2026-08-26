package tui

import (
	"strings"
	"testing"

	"github.com/itolstov/racg/internal/httpapi"
	"github.com/itolstov/racg/internal/store"
)

func TestRuleScopeLabelShowsStdinHash(t *testing.T) {
	argv := `["/bin/bash","-s"]`
	hash := "abc123"
	got := ruleScopeLabel(store.RuleRow{CmdArgvJSON: &argv, CmdStdinSHA256: &hash})
	if !strings.Contains(got, "argv="+argv) || !strings.Contains(got, "stdin_sha256="+hash) {
		t.Fatalf("label=%q", got)
	}
}

func TestNextJobIDCycles(t *testing.T) {
	s := newUIState(nil, nil)
	s.jobIDs = []string{"j1", "j2", "j3"}
	s.selectedJob = "j2"

	if got := s.nextJobID(1); got != "j3" {
		t.Fatalf("next +1 = %q, want j3", got)
	}
	if got := s.nextJobID(-1); got != "j1" {
		t.Fatalf("next -1 = %q, want j1", got)
	}

	s.selectedJob = "j1"
	if got := s.nextJobID(-1); got != "j3" {
		t.Fatalf("wrap -1 = %q, want j3", got)
	}
}

func TestNewUIStateShowsAllJobsByDefault(t *testing.T) {
	s := newUIState(nil, nil)
	if !s.showAllJobs {
		t.Fatalf("showAllJobs=false, want true")
	}
	if got := s.jobsModeLabel(); got != "Only running" {
		t.Fatalf("jobsModeLabel=%q", got)
	}
}

func TestNthJobID(t *testing.T) {
	s := newUIState(nil, nil)
	s.jobIDs = []string{"j1", "j2"}

	if got := s.nthJobID(1); got != "j1" {
		t.Fatalf("nth 1 = %q, want j1", got)
	}
	if got := s.nthJobID(2); got != "j2" {
		t.Fatalf("nth 2 = %q, want j2", got)
	}
	if got := s.nthJobID(3); got != "" {
		t.Fatalf("nth 3 = %q, want empty", got)
	}
}

func TestJobSelectionIndexKeepsSelectedID(t *testing.T) {
	ids := []string{"new", "middle", "old"}
	if got := jobSelectionIndex(ids, "middle", 0); got != 1 {
		t.Fatalf("index=%d, want 1", got)
	}
}

func TestJobSelectionIndexFallsBackToPreviousIndex(t *testing.T) {
	ids := []string{"new", "middle", "old"}
	if got := jobSelectionIndex(ids, "missing", 2); got != 2 {
		t.Fatalf("index=%d, want 2", got)
	}
}

func TestJobSelectionIndexFallsBackToFirst(t *testing.T) {
	ids := []string{"new", "middle", "old"}
	if got := jobSelectionIndex(ids, "missing", 10); got != 0 {
		t.Fatalf("index=%d, want 0", got)
	}
}

func TestJobListSignatureChangesOnStatusAndOrder(t *testing.T) {
	items := []httpapi.TUIRequest{
		{ID: "new", Status: "RUNNING", CreatedAt: "2026-02-11T01:01:00Z", Summary: "cmd"},
		{ID: "old", Status: "SUCCEEDED", CreatedAt: "2026-02-11T01:00:00Z", Summary: "cmd"},
	}
	base := jobListSignature(true, items)
	if base == "" {
		t.Fatal("empty signature")
	}
	if got := jobListSignature(true, append([]httpapi.TUIRequest(nil), items...)); got != base {
		t.Fatalf("same items signature changed")
	}
	if got := jobListSignature(false, items); got == base {
		t.Fatalf("mode change did not change signature")
	}

	items[0].Status = "KILLED"
	if got := jobListSignature(true, items); got == base {
		t.Fatalf("status change did not change signature")
	}

	items[0].Status = "RUNNING"
	items[0], items[1] = items[1], items[0]
	if got := jobListSignature(true, items); got == base {
		t.Fatalf("order change did not change signature")
	}
}

func TestShortStatus(t *testing.T) {
	if got := shortStatus("RUNNING"); got != "RUN" {
		t.Fatalf("RUNNING -> %q", got)
	}
	if got := shortStatus("SUCCEEDED"); got != "OK" {
		t.Fatalf("SUCCEEDED -> %q", got)
	}
	if got := shortStatus("PENDING_APPROVAL"); got != "PENDING_APPROVAL" {
		t.Fatalf("fallback -> %q", got)
	}
}

func TestJobViewModeLabel(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"combined", "[Combined] stdout stderr meta"},
		{"stdout", "Combined [stdout] stderr meta"},
		{"stderr", "Combined stdout [stderr] meta"},
		{"meta", "Combined stdout stderr [meta]"},
	}
	for _, tt := range tests {
		if got := jobViewModeLabel(tt.mode); got != tt.want {
			t.Fatalf("mode %q label=%q want %q", tt.mode, got, tt.want)
		}
	}
}

func TestJobFollowLabel(t *testing.T) {
	if got := jobFollowLabel(true); got != "Follow: on" {
		t.Fatalf("follow on label=%q", got)
	}
	if got := jobFollowLabel(false); got != "Follow: off" {
		t.Fatalf("follow off label=%q", got)
	}
}

func TestJobHeaderTextIncludesCommandSummary(t *testing.T) {
	info := httpapi.TUIRequestInfo{
		ID:       "req1",
		Status:   "SUCCEEDED",
		Summary:  "cmd.run bash -lc echo ok",
		ClientID: "cli",
	}
	got := jobHeaderText(info, true)
	for _, want := range []string{"job: req1", "status=SUCCEEDED", "follow=on", "client=cli", "cmd: cmd.run bash -lc echo ok"} {
		if !strings.Contains(got, want) {
			t.Fatalf("header missing %q:\n%s", want, got)
		}
	}
}

func TestPendingActionHintNamesKeyboardAndMouse(t *testing.T) {
	got := pendingActionHint()
	for _, want := range []string{"a once", "s session", "A always", "d deny", "mouse"} {
		if !strings.Contains(got, want) {
			t.Fatalf("hint=%q want %q", got, want)
		}
	}
}
