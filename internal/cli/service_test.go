package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestServiceCommandsExposeSafetyAndDeploymentBoundaries(t *testing.T) {
	var out, errOut bytes.Buffer
	authority := NewServiceAuthorityCmd(&out, &errOut)
	if code := authority.Run([]string{"--help"}); code != 0 {
		t.Fatalf("authority help code=%d stderr=%s", code, errOut.String())
	}
	for _, want := range []string{
		"privileged service authority/executor",
		"authority-owned private state",
		"admin socket is created with mode 0600",
		"broker UID",
		"UNCERTAIN",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("authority help missing %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	errOut.Reset()
	broker := NewServiceBrokerCmd(&out, &errOut)
	if code := broker.Run([]string{"--help"}); code != 0 {
		t.Fatalf("broker help code=%d stderr=%s", code, errOut.String())
	}
	for _, want := range []string{
		"unprivileged signed-protocol relay",
		"cannot authorize",
		"expected authority process UID",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("broker help missing %q:\n%s", want, out.String())
		}
	}
}

func TestServiceAuthorityRejectsInvalidFlagConfiguration(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := NewServiceAuthorityCmd(&out, &errOut)
	code := cmd.run(context.Background(), []string{
		"--server-id", "server",
		"--state-dir", "relative-state",
		"--socket", "/tmp/authority.sock",
		"--admin-socket", "/tmp/authority-admin.sock",
		"--broker-uid", "0",
		"--broker-gid", "0",
		"--admin-uid", "0",
		"--admin-gid", "0",
	})
	if code != 2 || !strings.Contains(errOut.String(), "absolute canonical path") {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
}
