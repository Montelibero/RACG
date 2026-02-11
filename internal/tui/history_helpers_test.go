package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/store"
)

func TestHistorySessionLabel(t *testing.T) {
	sess := store.Session{
		ID:        "sess-1",
		StartedAt: time.Date(2026, 2, 11, 17, 45, 25, 0, time.UTC),
	}
	got := historySessionLabel(sess)
	if !strings.Contains(got, "sess-1") {
		t.Fatalf("label=%q", got)
	}
	if !strings.Contains(got, "2026-02-11T17:45:25Z") {
		t.Fatalf("label=%q", got)
	}
}
