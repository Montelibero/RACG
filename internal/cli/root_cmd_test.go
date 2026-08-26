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

func TestRootHelpIncludesFileAndConfigExamples(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)

	if code := root.Run([]string{"--help"}); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}

	got := out.String()
	for _, want := range []string{
		"racg file read /path/file.txt",
		"racg file patch /path/file.txt --diff-file /tmp/change.patch",
		"racg file upload ./local.bin /srv/remote.bin",
		"racg file download /srv/remote.bin ./local.bin",
		"racg config set values.yaml image.tag v1.2.3 --format yaml",
		"racg run -- bash -lc",
		"racg request wait <id>",
		"--execution-timeout 2m",
		"--status-interval 30s",
		"--reconnect-timeout 5m",
		"racg run --script ./maintenance.sh",
		"racg run --stdin-file ./query.sql",
		"racg run --script-stdin",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("help missing %q:\n%s", want, got)
		}
	}
}
