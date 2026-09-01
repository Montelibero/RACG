package outputfilter

import (
	"strings"
	"testing"
)

func TestRedactMasksCommonSecretForms(t *testing.T) {
	input := strings.Join([]string{
		"PASSWORD=hunter2",
		`{"api_key":"abc123","name":"visible"}`,
		"Authorization: Bearer token.value",
		"url=https://alice:secret@example.test/path",
		"github_pat_0123456789abcdefghijklmnopqrstuvwxyz",
	}, "\n")

	got := Redact(input)
	for _, secret := range []string{"hunter2", "abc123", "token.value", "alice:secret", "github_pat_0123456789abcdefghijklmnopqrstuvwxyz"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted output still contains %q:\n%s", secret, got)
		}
	}
	if !strings.Contains(got, `"name":"visible"`) || strings.Count(got, Placeholder) < 5 {
		t.Fatalf("unexpected redacted output:\n%s", got)
	}
}

func TestRedactMasksPrivateKeyBlock(t *testing.T) {
	input := "before\n-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----\nafter\n"
	got := Redact(input)
	if strings.Contains(got, "secret material") || got != "before\n[REDACTED]\n\n\nafter\n" {
		t.Fatalf("redacted output=%q", got)
	}
}
