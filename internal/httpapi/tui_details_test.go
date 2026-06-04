package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTUIDetailsForCmdRunShowsStructuredPreviewAndRiskHints(t *testing.T) {
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv":        []string{"bash", "-lc", "sudo kubectl delete secret app-secret"},
			"cwd":         "/repo",
			"timeout_sec": 45,
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := tuiDetails(requestRecord{Op: b})

	for _, want := range []string{
		"cwd: /repo",
		"timeout_sec: 45",
		"argv:",
		"  [0] bash",
		"  [1] -lc",
		"  [2] sudo kubectl delete secret app-secret",
		"review_hints: sudo, delete, secret",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}
