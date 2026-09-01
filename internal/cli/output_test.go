package cli

import "testing"

func TestNumberOutputLinesPreservesContentAndFinalNewline(t *testing.T) {
	got := numberOutputLines("global\n    maxconn 2000\n")
	want := "1 | global\n2 |     maxconn 2000\n"
	if got != want {
		t.Fatalf("numbered output=%q want %q", got, want)
	}
}
