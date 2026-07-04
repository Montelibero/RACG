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

func TestCLILoginWithoutNameStoresAutoNamedProfileAndRunUsesActive(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("RACG_CLIENT_CONFIG", "")

	var createdWithAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/session/open":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"session_id":"sess1","session_token":"tok-profile","expires_at":"2030-01-01T00:00:00Z"}`))
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
	code := root.Run([]string{"login", "--host", ts.URL, "--pairing-code", "ABC123"})
	if code != 0 {
		t.Fatalf("login code=%d stderr=%s", code, errOut.String())
	}
	profile := autoClientProfileName(ts.URL)
	for _, want := range []string{
		"profile: " + profile,
		"config_path: " + filepath.Join(configHome, "racg", "clients", profile+".json"),
		"hint: use --name " + profile,
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("login stdout=%q want %q", out.String(), want)
		}
	}
	if _, err := os.Stat(filepath.Join(configHome, "racg", "clients", profile+".json")); err != nil {
		t.Fatalf("profile config not written: %v", err)
	}

	out.Reset()
	errOut.Reset()
	code = root.Run([]string{"run", "--no-wait", "--", "/bin/echo", "hi"})
	if code != 0 {
		t.Fatalf("run code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}
	if createdWithAuth != "Bearer tok-profile" {
		t.Fatalf("Authorization=%q", createdWithAuth)
	}
}

func TestCLILoginAcceptsBareHostAndUsesHostProfileName(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("RACG_CLIENT_CONFIG", "")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/session/open" {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"sess1","session_token":"tok-profile","expires_at":"2030-01-01T00:00:00Z"}`))
	}))
	defer ts.Close()
	bareHost := strings.TrimPrefix(ts.URL, "http://")

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"login", "--host", bareHost, "--pairing-code", "ABC123"})
	if code != 0 {
		t.Fatalf("login code=%d stderr=%s", code, errOut.String())
	}
	profile := autoClientProfileName(bareHost)
	if !strings.Contains(out.String(), "host: "+ts.URL) {
		t.Fatalf("stdout=%q want normalized host %q", out.String(), ts.URL)
	}
	if !strings.Contains(out.String(), "profile: "+profile) {
		t.Fatalf("stdout=%q want profile %q", out.String(), profile)
	}
	if _, err := os.Stat(filepath.Join(configHome, "racg", "clients", profile+".json")); err != nil {
		t.Fatalf("profile config not written: %v", err)
	}
}

func TestAutoClientProfileNameOmitsDefaultPort(t *testing.T) {
	if got := autoClientProfileName("server"); got != "server" {
		t.Fatalf("profile=%q want server", got)
	}
	if got := autoClientProfileName("http://server:8777"); got != "server" {
		t.Fatalf("profile=%q want server", got)
	}
	if got := autoClientProfileName("http://server:8788"); got != "server" {
		t.Fatalf("profile=%q want server", got)
	}
	if got := autoClientProfileName("server:8788"); got != "server" {
		t.Fatalf("profile=%q want server", got)
	}
}

func TestResolveClientAuthNormalizesBareHostFlag(t *testing.T) {
	host, token, err := resolveClientAuth("server", "tok")
	if err != nil {
		t.Fatalf("resolveClientAuth: %v", err)
	}
	if host != "http://server:8777" || token != "tok" {
		t.Fatalf("host=%q token=%q", host, token)
	}

	host, token, err = resolveClientAuth("server:8788", "tok")
	if err != nil {
		t.Fatalf("resolveClientAuth: %v", err)
	}
	if host != "http://server:8788" || token != "tok" {
		t.Fatalf("host=%q token=%q", host, token)
	}
}

func TestCLIUseSwitchesActiveClientProfile(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("RACG_CLIENT_CONFIG", "")

	if _, err := saveNamedClientConfig("server-a", clientConfig{Host: "http://a", Token: "tok-a"}); err != nil {
		t.Fatalf("save server-a: %v", err)
	}
	if _, err := saveNamedClientConfig("server-b", clientConfig{Host: "http://b", Token: "tok-b"}); err != nil {
		t.Fatalf("save server-b: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"use", "server-b"})
	if code != 0 {
		t.Fatalf("use code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "active_profile: server-b") {
		t.Fatalf("stdout=%q", out.String())
	}

	host, token, err := resolveClientAuth("", "")
	if err != nil {
		t.Fatalf("resolveClientAuth: %v", err)
	}
	if host != "http://b:8777" || token != "tok-b" {
		t.Fatalf("host=%q token=%q", host, token)
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
