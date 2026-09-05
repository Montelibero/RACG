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
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
)

func TestFileEditCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, op, original, want, decision, diagnostic string
		payload                                        map[string]any
	}{
		{name: "patch", op: "fs.patch_unified", original: "old\n", want: "new\n", payload: map[string]any{"diff": "@@ -1 +1 @@\n-old\n+new\n"}},
		{name: "patch mismatch", op: "fs.patch_unified", original: "old\n", want: "old\n", diagnostic: "hunk delete mismatch", payload: map[string]any{"diff": "@@ -1 +1 @@\n-other\n+new\n"}},
		{name: "patch out of range", op: "fs.patch_unified", original: "old\n", want: "old\n", diagnostic: "hunk out of range", payload: map[string]any{"diff": "@@ -9 +9 @@\n-old\n+new\n"}},
		{name: "patch denied", op: "fs.patch_unified", original: "old\n", want: "old\n", decision: "DENY", payload: map[string]any{"diff": "@@ -1 +1 @@\n-old\n+new\n"}},
		{name: "config no backup", op: "conf.set", original: "VALUE=old\n", want: "VALUE=new\n", payload: map[string]any{"format": "env", "key": "VALUE", "value": "new", "backup": false}},
		{name: "config invalid format", op: "conf.set", original: "VALUE=old\n", want: "VALUE=old\n", diagnostic: "unsupported format", payload: map[string]any{"format": "unknown", "key": "VALUE", "value": "new"}},
		{name: "config denied", op: "conf.set", original: "VALUE=old\n", want: "VALUE=old\n", decision: "DENY", payload: map[string]any{"format": "env", "key": "VALUE", "value": "new"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "input")
			if err := os.WriteFile(path, []byte(tc.original), 0o640); err != nil {
				t.Fatal(err)
			}
			cfg := config.Defaults()
			tokens := auth.NewTokenManager(nil)
			token, _ := tokens.Issue("edit-session", "edit-client", time.Hour)
			api := New(cfg, WithTokenManager(tokens))
			tc.payload["path"] = path
			body, err := json.Marshal(map[string]any{"op": map[string]any{"type": tc.op, "payload": tc.payload}})
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
			before, err := os.ReadFile(path)
			if err != nil || string(before) != tc.original {
				t.Fatalf("file changed before approval: %q %v", before, err)
			}
			decision := tc.decision
			if decision == "" {
				decision = "ALLOW_ONCE"
			}
			if err := api.DecideForTUI(created.RequestID, decision); err != nil {
				t.Fatal(err)
			}
			waitRequestTerminalForTest(t, api, token, created.RequestID)
			info, _ := api.GetRequestInfoForTUI(created.RequestID)
			if decision == "DENY" {
				if info.Status != "DENIED" || info.Result != nil {
					t.Fatalf("denied request executed: %+v", info)
				}
			} else {
				result := info.Result
				if result == nil {
					t.Fatal("missing result")
				}
				if tc.diagnostic != "" {
					if info.Status != "FAILED" || result.ExitCode != -1 || !strings.Contains(result.Stderr, tc.diagnostic) || result.Stdout != "" {
						t.Fatalf("failure=%+v", result)
					}
				} else {
					if info.Status != "SUCCEEDED" || result.ExitCode != 0 || result.Stderr != "" {
						t.Fatalf("result=%+v", result)
					}
					wantOutput := "patched"
					if tc.op == "conf.set" {
						wantOutput = "path: " + path + "\nformat: env\nkey: VALUE\ncreated: false\nfile_created: false\nold: old\nnew: new"
					}
					if result.Stdout != wantOutput {
						t.Fatalf("stdout=%q want=%q", result.Stdout, wantOutput)
					}
				}
				for _, pair := range [][2]string{{result.StdoutSHA256, result.Stdout}, {result.StderrSHA256, result.Stderr}} {
					sum := sha256.Sum256([]byte(pair[1]))
					if pair[0] != hex.EncodeToString(sum[:]) {
						t.Fatalf("wrong hash for %q", pair[1])
					}
				}
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != tc.want {
				t.Fatalf("file=%q want=%q err=%v", got, tc.want, err)
			}
			stat, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if stat.Mode().Perm() != 0o640 {
				t.Fatalf("mode=%o", stat.Mode().Perm())
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("unexpected backup or temp file: %v", entries)
			}
		})
	}
}
