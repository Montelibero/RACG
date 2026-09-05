package executor

import "testing"

func TestApplyUnifiedPatchTextInsertsIntoEmptyFile(t *testing.T) {
	patch := `--- a/haproxy.cfg
+++ b/haproxy.cfg
@@ -0,0 +1,2 @@
+global
+    maxconn 2000
`
	got, err := applyUnifiedPatchText("", patch)
	if err != nil {
		t.Fatalf("applyUnifiedPatchText: %v", err)
	}
	if want := "global\n    maxconn 2000\n"; got != want {
		t.Fatalf("result=%q, want %q", got, want)
	}
}

func TestApplyUnifiedPatchTextHonorsNoNewlineMarker(t *testing.T) {
	patch := "@@ -0,0 +1 @@\n+global\n\\ No newline at end of file\n"
	got, err := applyUnifiedPatchText("", patch)
	if err != nil {
		t.Fatalf("applyUnifiedPatchText: %v", err)
	}
	if got != "global" {
		t.Fatalf("result=%q, want no trailing newline", got)
	}
}
