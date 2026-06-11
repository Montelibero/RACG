package configedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetEnvUpdatesExistingKeyCreatesBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("# app\nPORT=3000\nDEBUG=false\n"), 0o644); err != nil {
		t.Fatalf("write env: %v", err)
	}

	res, err := Set(ConfigSet{
		Path:      path,
		Format:    "env",
		Key:       "PORT",
		Value:     "8080",
		ValueType: "string",
		Backup:    true,
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := readFile(t, path)
	if got != "# app\nPORT=8080\nDEBUG=false\n" {
		t.Fatalf("env=%q", got)
	}
	if res.OldValue != "3000" || res.NewValue != "8080" || res.BackupPath == "" {
		t.Fatalf("result=%+v", res)
	}
	if readFile(t, res.BackupPath) != "# app\nPORT=3000\nDEBUG=false\n" {
		t.Fatalf("backup content mismatch")
	}
}

func TestSetEnvAddsMissingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("PORT=3000\n"), 0o644); err != nil {
		t.Fatalf("write env: %v", err)
	}

	res, err := Set(ConfigSet{Path: path, Format: "env", Key: "HOST", Value: "127.0.0.1", ValueType: "string"})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := readFile(t, path)
	if got != "PORT=3000\nHOST=127.0.0.1\n" {
		t.Fatalf("env=%q", got)
	}
	if !res.Created || res.OldValue != "" {
		t.Fatalf("result=%+v", res)
	}
}

func TestSetJSONNestedBoolKeepsValidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"server":{"host":"127.0.0.1","debug":false}}`), 0o644); err != nil {
		t.Fatalf("write json: %v", err)
	}

	res, err := Set(ConfigSet{Path: path, Format: "json", Key: "server.debug", Value: "true", ValueType: "bool"})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := readFile(t, path)
	if !strings.Contains(got, `"debug": true`) || !strings.HasSuffix(got, "\n") {
		t.Fatalf("json=%q", got)
	}
	if res.OldValue != "false" || res.NewValue != "true" {
		t.Fatalf("result=%+v", res)
	}
}

func TestSetYAMLNestedStringCreatesMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(path, []byte("image:\n  repository: app\n"), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	res, err := Set(ConfigSet{Path: path, Format: "yaml", Key: "image.tag", Value: "v1.2.3", ValueType: "string"})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := readFile(t, path)
	for _, want := range []string{"image:", "repository: app", "tag: v1.2.3"} {
		if !strings.Contains(got, want) {
			t.Fatalf("yaml missing %q:\n%s", want, got)
		}
	}
	if !res.Created {
		t.Fatalf("result=%+v", res)
	}
}

func TestSetRejectsInvalidYAMLInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("image: [unterminated\n"), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	if _, err := Set(ConfigSet{Path: path, Format: "yaml", Key: "image.tag", Value: "v1", ValueType: "string"}); err == nil {
		t.Fatalf("expected invalid yaml error")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
