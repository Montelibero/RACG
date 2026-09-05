package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/tui"
)

func TestServeReturnsWhenListenPortIsAlreadyInUse(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- NewServeCmd(&stdout, &stderr).Run([]string{
			"-listen-addr", "127.0.0.1",
			"-port", strconv.Itoa(port),
		})
	}()

	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit code=%d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "server error:") {
			t.Fatalf("stderr=%q, want server error", stderr.String())
		}
		if strings.Contains(stdout.String(), "listening=") {
			t.Fatalf("stdout reported a listener that never started: %q", stdout.String())
		}
	case <-time.After(time.Second):
		t.Fatal("serve hung after listen failed")
	}
}

func TestApprovalBoundaryHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := NewServeCmd(&stdout, &stderr).Run([]string{"--help"}); code != 2 {
		t.Fatalf("help exit=%d", code)
	}
	for _, help := range []string{usage(), stderr.String()} {
		for _, want := range []string{"local to the server TUI", "403 REMOTE_DECISION_DISABLED", "rules may still auto-approve", "audit transaction is saved"} {
			if !strings.Contains(help, want) {
				t.Fatalf("help missing %q: %s", want, help)
			}
		}
	}
}

func TestServeInteractiveLifecycle(t *testing.T) {
	for _, exit := range []string{"ui-return", "ui-exit", "context-cancel"} {
		t.Run(exit, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			cmd := NewServeCmd(&stdout, &stderr)
			var address string
			cmd.runUI = func(uiCtx context.Context, cfg tui.ServeUIConfig) error {
				address = cfg.Listen
				if cfg.API == nil || cfg.Store == nil || cfg.ExitFunc == nil {
					t.Fatal("interactive UI did not receive its local backend")
				}
				if cfg.Profile != "compat" || cfg.DBPath != config.ProfileDBPath("compat") {
					t.Fatalf("profile configuration: %+v", cfg)
				}
				for _, want := range []string{"listening=http://" + address, "profile=compat", "db_path=" + cfg.DBPath, "pairing_code=" + cfg.API.PairingCode()} {
					if !strings.Contains(stdout.String(), want) {
						t.Fatalf("startup output missing %q: %s", want, stdout.String())
					}
				}
				client := &http.Client{Timeout: time.Second}
				defer client.CloseIdleConnections()
				resp, err := client.Get("http://" + address + "/healthz")
				if err != nil {
					t.Fatalf("UI started before server became reachable: %v", err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
					t.Fatalf("health: status=%d body=%q err=%v", resp.StatusCode, body, err)
				}
				switch exit {
				case "ui-exit":
					cfg.ExitFunc()
				case "context-cancel":
					cancel()
				default:
					return nil
				}
				select {
				case <-uiCtx.Done():
				case <-time.After(time.Second):
					t.Fatal("UI did not receive cancellation")
				}
				return nil
			}
			if code := cmd.run(ctx, []string{"--profile", "compat", "--port", "0"}); code != 0 {
				t.Fatalf("exit=%d stderr=%s", code, stderr.String())
			}
			if address == "" {
				t.Fatal("UI was not started")
			}
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("server did not release its listener: %v", err)
			}
			listener.Close()
		})
	}
}

func TestServeInteractiveAgentRoundTrip(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("RACG_CLIENT_CONFIG", filepath.Join(t.TempDir(), "client.json"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := NewServeCmd(&stdout, &stderr)
	cmd.runUI = func(_ context.Context, cfg tui.ServeUIConfig) error {
		var out, errOut bytes.Buffer
		root := NewRoot(&out, &errOut)
		if code := root.Run([]string{"login", "--host", "http://" + cfg.Listen, "--pairing-code", cfg.API.PairingCode(), "--client-id", "compat-agent"}); code != 0 {
			t.Fatalf("login=%d stderr=%s", code, errOut.String())
		}
		for _, decision := range []string{"ALLOW_ONCE", "DENY"} {
			out.Reset()
			errOut.Reset()
			if code := root.Run([]string{"run", "--no-wait", "--", "/bin/echo", "compat-round-trip"}); code != 0 {
				t.Fatalf("run=%d stderr=%s", code, errOut.String())
			}
			pending := cfg.API.ListPendingForTUI()
			if len(pending) != 1 || pending[0].ClientID != "compat-agent" {
				t.Fatalf("pending=%+v; Allow once must not create a reusable grant", pending)
			}
			id := pending[0].ID
			if err := cfg.API.DecideForTUI(id, decision); err != nil {
				t.Fatal(err)
			}
			for {
				info, ok := cfg.API.GetRequestInfoForTUI(id)
				if !ok {
					t.Fatal("request disappeared")
				}
				if decision == "DENY" {
					if info.Status != "DENIED" || info.Result != nil {
						t.Fatalf("denied request executed: %+v", info)
					}
					break
				}
				if info.Result != nil {
					if info.Status != "SUCCEEDED" || info.Result.Stdout != "compat-round-trip\n" {
						t.Fatalf("execution result=%+v", info.Result)
					}
					out.Reset()
					errOut.Reset()
					if code := root.Run([]string{"request", "logs", id}); code != 0 || !strings.Contains(out.String(), "compat-round-trip") {
						t.Fatalf("logs=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("execution did not finish")
				case <-time.After(10 * time.Millisecond):
				}
			}
			history, err := cfg.Store.ListSessionHistoryItems(ctx, pending[0].SessionID, 100)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, item := range history {
				if item.RequestID != id {
					continue
				}
				found = true
				if item.Decision == nil || *item.Decision != decision || item.DecisionSource == nil || *item.DecisionSource != "tui" {
					t.Fatalf("stored decision=%+v", item)
				}
			}
			if !found {
				t.Fatal("decision missing from history")
			}
		}
		return nil
	}
	if code := cmd.run(ctx, []string{"--port", "0"}); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}

func TestServeInvalidConfigurationDoesNotStartUI(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	cmd := NewServeCmd(&stdout, &stderr)
	cmd.runUI = func(context.Context, tui.ServeUIConfig) error {
		t.Fatal("UI started with invalid configuration")
		return fmt.Errorf("unexpected UI")
	}
	if code := cmd.Run([]string{"--max-transfer-bytes", "0"}); code != 1 || !strings.Contains(stderr.String(), "server init failed:") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}
