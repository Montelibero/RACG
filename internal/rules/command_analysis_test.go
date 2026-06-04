package rules

import "testing"

func TestAnalyzeCmdRunShellSplitsCommandSegments(t *testing.T) {
	op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"bash", "-lc", "docker stop nginx && echo ok && rm /"},
	})}

	analysis := AnalyzeCommandOp(op)
	if analysis.Unsupported != "" {
		t.Fatalf("unsupported=%q", analysis.Unsupported)
	}
	if len(analysis.Segments) != 3 {
		t.Fatalf("segments=%d want 3: %#v", len(analysis.Segments), analysis.Segments)
	}

	want := [][]string{
		{"docker", "stop", "nginx"},
		{"echo", "ok"},
		{"rm", "/"},
	}
	for i, wantArgv := range want {
		if got := joinNUL(analysis.Segments[i].Argv); got != joinNUL(wantArgv) {
			t.Fatalf("segment %d argv=%q want=%q", i, analysis.Segments[i].Argv, wantArgv)
		}
	}
}

func TestAnalyzeCmdRunShellMarksRedirectsUnsupported(t *testing.T) {
	op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"sh", "-c", "echo ok > /tmp/out"},
	})}

	analysis := AnalyzeCommandOp(op)
	if len(analysis.Segments) != 1 {
		t.Fatalf("segments=%d want 1", len(analysis.Segments))
	}
	if analysis.Segments[0].Unsupported == "" {
		t.Fatalf("redirect segment should be unsupported: %#v", analysis.Segments[0])
	}
}

func TestAnalyzeCmdRunPlainArgvIsSingleSegment(t *testing.T) {
	op := Op{Type: "cmd.run", Payload: mustJSON(t, map[string]any{
		"argv": []string{"docker", "stop", "nginx"},
	})}

	analysis := AnalyzeCommandOp(op)
	if len(analysis.Segments) != 1 {
		t.Fatalf("segments=%d want 1", len(analysis.Segments))
	}
	if got := joinNUL(analysis.Segments[0].Argv); got != "docker\x00stop\x00nginx" {
		t.Fatalf("argv=%q", analysis.Segments[0].Argv)
	}
}

func joinNUL(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += "\x00"
		}
		out += x
	}
	return out
}
