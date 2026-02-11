package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootUsageIncludesQuickStartServeCommand(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)

	if code := root.Run(nil); code != 2 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}

	want := "sudo racg serve -listen-addr 127.0.0.1 -port 8777"
	if !strings.Contains(errOut.String(), want) {
		t.Fatalf("stderr=%q, want contains %q", errOut.String(), want)
	}
}
