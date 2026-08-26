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

func TestPendingDetailsCacheLoadsSelectedRequestOnce(t *testing.T) {
	s := newUIState(nil, nil)
	loads := 0
	load := func() (string, bool) {
		loads++
		return "large exact script", true
	}
	first, ok := s.cachedPendingDetails("req-1", load)
	if !ok || first != "large exact script" {
		t.Fatalf("first=%q ok=%t", first, ok)
	}
	second, ok := s.cachedPendingDetails("req-1", load)
	if !ok || second != first || loads != 1 {
		t.Fatalf("second=%q ok=%t loads=%d", second, ok, loads)
	}
	if _, ok := s.cachedPendingDetails("req-2", load); !ok || loads != 2 {
		t.Fatalf("new selection ok=%t loads=%d", ok, loads)
	}
}
