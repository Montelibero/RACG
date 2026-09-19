package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeadlessKeygenAndPublicKey(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "device.key")
	var stdout, stderr bytes.Buffer
	if _, code := runAppCommand([]string{
		"keygen",
		"--key", keyPath,
		"--device-id", "test-device",
		"--passphrase", "correct horse",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("keygen code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "device_id=test-device") || !strings.Contains(stdout.String(), "public_key=") {
		t.Fatalf("keygen output=%q", stdout.String())
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("key mode=%v", got)
	}

	stdout.Reset()
	stderr.Reset()
	if _, code := runAppCommand([]string{
		"public-key",
		"--key", keyPath,
		"--passphrase", "correct horse",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("public-key code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "device_id=test-device") || !strings.Contains(stdout.String(), "public_key=") {
		t.Fatalf("public-key output=%q", stdout.String())
	}
}

func TestHeadlessCommandsRequireKeyAndPassphrase(t *testing.T) {
	for _, command := range []string{"keygen", "public-key"} {
		var stdout, stderr bytes.Buffer
		if _, code := runAppCommand([]string{command}, &stdout, &stderr); code != 2 {
			t.Fatalf("%s code=%d stderr=%s", command, code, stderr.String())
		}
	}
}
