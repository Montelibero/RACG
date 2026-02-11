package tui

import "testing"

func TestPendingSelectionIndexPrefersSameID(t *testing.T) {
	ids := []string{"req-1", "req-2", "req-3"}
	got := pendingSelectionIndex(ids, "req-2", 0)
	if got != 1 {
		t.Fatalf("index=%d, want 1", got)
	}
}

func TestPendingSelectionIndexFallsBackToPreviousIndex(t *testing.T) {
	ids := []string{"req-1", "req-2", "req-3"}
	got := pendingSelectionIndex(ids, "missing", 2)
	if got != 2 {
		t.Fatalf("index=%d, want 2", got)
	}
}

func TestPendingSelectionIndexFallsBackToFirst(t *testing.T) {
	ids := []string{"req-1", "req-2"}
	got := pendingSelectionIndex(ids, "missing", 10)
	if got != 0 {
		t.Fatalf("index=%d, want 0", got)
	}
}

func TestPendingSelectionIndexEmpty(t *testing.T) {
	got := pendingSelectionIndex(nil, "req-1", 0)
	if got != -1 {
		t.Fatalf("index=%d, want -1", got)
	}
}
