package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
)

// Pin the HTTP/TUI contract before moving file execution out of the HTTP layer.
func TestFSReadCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, content                 string
		requested                     int
		want                          string
		truncated, missing, directory bool
	}{
		{name: "empty"},
		{name: "exact boundary", content: "abcd", want: "abcd"},
		{name: "server cap", content: "abcdef", requested: 100, want: "abcd", truncated: true},
		{name: "request cap", content: "abcdef", requested: 2, want: "ab", truncated: true},
		{name: "default cap", content: "abcdef", want: "abcd", truncated: true},
		{name: "negative cap", content: "abcdef", requested: -1, want: "abcd", truncated: true},
		{name: "missing", missing: true},
		{name: "read error", directory: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if tc.directory {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.Defaults()
			cfg.MaxOutputBytes = 4
			tokens := auth.NewTokenManager(nil)
			token, _ := tokens.Issue("read-session", "read-client", time.Hour)
			api := New(cfg, WithTokenManager(tokens))
			body, err := json.Marshal(map[string]any{"op": map[string]any{
				"type": "fs.read", "payload": map[string]any{"path": path, "max_bytes": tc.requested},
			}})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/requests", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			rw := httptest.NewRecorder()
			api.Handler().ServeHTTP(rw, req)
			if rw.Code != http.StatusOK {
				t.Fatalf("create=%d %s", rw.Code, rw.Body.String())
			}
			var created struct {
				RequestID string `json:"request_id"`
			}
			if err := json.Unmarshal(rw.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
			if err := api.DecideForTUI(created.RequestID, "ALLOW_ONCE"); err != nil {
				t.Fatal(err)
			}
			waitRequestTerminalForTest(t, api, token, created.RequestID)
			info, _ := api.GetRequestInfoForTUI(created.RequestID)
			got := info.Result
			if got == nil {
				t.Fatal("missing result")
			}
			if got.Stdout != tc.want || got.StdoutTruncated != tc.truncated || got.StderrTruncated {
				t.Fatalf("output=%+v", got)
			}
			wantStatus, wantExit := "SUCCEEDED", 0
			if tc.missing || tc.directory {
				wantStatus, wantExit = "FAILED", -1
				if got.Stderr == "" {
					t.Fatal("missing failure diagnostic")
				}
			} else if got.Stderr != "" {
				t.Fatalf("stderr=%s", got.Stderr)
			}
			if info.Status != wantStatus || got.Status != wantStatus || got.ExitCode != wantExit {
				t.Fatalf("status=%s result=%+v", info.Status, got)
			}
			for _, pair := range [][2]string{{got.StdoutSHA256, tc.content}, {got.StderrSHA256, got.Stderr}} {
				sum := sha256.Sum256([]byte(pair[1]))
				if pair[0] != hex.EncodeToString(sum[:]) {
					t.Fatalf("hash=%s for %q", pair[0], pair[1])
				}
			}
			start, e1 := time.Parse(time.RFC3339Nano, got.StartedAt)
			end, e2 := time.Parse(time.RFC3339Nano, got.FinishedAt)
			if e1 != nil || e2 != nil || end.Before(start) || got.DurationMs < 0 {
				t.Fatalf("invalid timing: %+v", got)
			}
		})
	}
}
