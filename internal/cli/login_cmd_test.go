package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLILoginStoresClientConfigAndRunUsesIt(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "client.json")
	t.Setenv("RACG_CLIENT_CONFIG", configPath)

	var createdWithAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/session/open":
			var req struct {
				ClientID    string `json:"client_id"`
				PairingCode string `json:"pairing_code"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode login: %v", err)
			}
			if req.ClientID != "agent-1" || req.PairingCode != "ABC123" {
				t.Fatalf("login req=%+v", req)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"session_id":"sess1","session_token":"tok1","expires_at":"2030-01-01T00:00:00Z"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/requests":
			createdWithAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"PENDING_APPROVAL"}`))
		default:
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"login", "--host", ts.URL, "--pairing-code", "ABC123", "--client-id", "agent-1"})
	if code != 0 {
		t.Fatalf("login code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "logged_in=true") {
		t.Fatalf("login stdout=%q", out.String())
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("config not written: %v", err)
	}

	out.Reset()
	errOut.Reset()
	code = root.Run([]string{"run", "--no-wait", "--", "/bin/echo", "hi"})
	if code != 0 {
		t.Fatalf("run code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}
	if createdWithAuth != "Bearer tok1" {
		t.Fatalf("Authorization=%q", createdWithAuth)
	}
}

func TestCLILogoutRemovesClientConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "client.json")
	t.Setenv("RACG_CLIENT_CONFIG", configPath)
	if err := saveClientConfig(clientConfig{Host: "http://example", Token: "tok"}); err != nil {
		t.Fatalf("saveClientConfig: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"logout"})
	if code != 0 {
		t.Fatalf("logout code=%d stderr=%s", code, errOut.String())
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("config still exists err=%v", err)
	}
}

func TestCLISessionStatusUsesStoredClientConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "client.json")
	t.Setenv("RACG_CLIENT_CONFIG", configPath)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/session/me" {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok1" {
			t.Fatalf("Authorization=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"sess1","client_id":"agent-1","expires_at":"2030-01-01T00:00:00Z","privilege_mode":"root"}`))
	}))
	defer ts.Close()

	if err := saveClientConfig(clientConfig{Host: ts.URL, Token: "tok1"}); err != nil {
		t.Fatalf("saveClientConfig: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"session", "status"})
	if code != 0 {
		t.Fatalf("session status code=%d stderr=%s", code, errOut.String())
	}
	for _, want := range []string{"host: " + ts.URL, "session_id: sess1", "client_id: agent-1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout=%q want %q", out.String(), want)
		}
	}
}
