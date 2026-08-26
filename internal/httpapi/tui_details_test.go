package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/rules"
)

func TestTUIDetailsForCmdRunShowsStructuredPreviewAndRiskHints(t *testing.T) {
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv":        []string{"bash", "-lc", "sudo kubectl delete secret app-secret"},
			"cwd":         "/repo",
			"timeout_sec": 45,
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := tuiDetails(requestRecord{Op: b})

	for _, want := range []string{
		"operation: RUN COMMAND",
		"effect: executes argv on the server",
		"cwd: /repo",
		"timeout_sec: 45",
		"argv:",
		"  [0] bash",
		"  [1] -lc",
		"  [2] sudo kubectl delete secret app-secret",
		"review_hints: sudo, delete, secret",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestTUIDetailsForCmdRunShowsStdinMetadataAndExactContent(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
	api := New(cfg)
	if err := os.MkdirAll(api.transferDir(), 0o700); err != nil {
		t.Fatalf("mkdir transfers: %v", err)
	}
	uploadID := "11111111-1111-4111-8111-111111111111"
	content := "select '$VALUE', '{{json .Mounts}}';\n"
	if err := os.WriteFile(api.uploadDataPath(uploadID), []byte(content), 0o600); err != nil {
		t.Fatalf("write staged stdin: %v", err)
	}
	op, _ := json.Marshal(map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"isql"}, "stdin_upload_id": uploadID,
			"stdin_size": len(content), "stdin_sha256": strings.Repeat("a", 64),
		},
	})

	got := api.tuiDetails(requestRecord{Op: op})
	for _, want := range []string{
		"stdin:", "size:", "sha256: " + strings.Repeat("a", 64),
		"content:", content,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, uploadID) {
		t.Fatalf("details expose staging id:\n%s", got)
	}
}

func TestTUIDetailsForFSReadShowsOperationAndEffect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "haproxy.cfg")
	if err := os.WriteFile(path, []byte("global\n    maxconn 2000\n"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	op := map[string]any{
		"type": "fs.read",
		"payload": map[string]any{
			"path":      path,
			"max_bytes": 128,
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := tuiDetails(requestRecord{Op: b})

	for _, want := range []string{
		"operation: READ FILE",
		"effect: reads file content only",
		"path: " + path,
		"max_bytes: 128",
		"preview:",
		"global",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestTUIDetailsForFSPatchShowsOperationAndEffect(t *testing.T) {
	op := map[string]any{
		"type": "fs.patch_unified",
		"payload": map[string]any{
			"path": "/apps/haproxy/haproxy.cfg",
			"diff": "--- a/haproxy.cfg\n+++ b/haproxy.cfg\n@@\n-global\n+global\n",
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := tuiDetails(requestRecord{Op: b})

	for _, want := range []string{
		"operation: PATCH FILE",
		"effect: applies unified diff to one file",
		"path: /apps/haproxy/haproxy.cfg",
		"diff:",
		"--- a/haproxy.cfg",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestTUIDetailsForFileTransfersShowsDirectionAndMetadata(t *testing.T) {
	tests := []struct {
		op   map[string]any
		want []string
	}{
		{
			op: map[string]any{"type": "fs.upload", "payload": map[string]any{
				"path": "/srv/archive.bin", "upload_id": "hidden", "size": 42,
				"sha256": strings.Repeat("a", 64), "mode": "0640",
			}},
			want: []string{"operation: UPLOAD FILE", "effect: atomically writes uploaded content to the server", "path: /srv/archive.bin", "size: 42 bytes", "sha256: " + strings.Repeat("a", 64), "mode: 0640"},
		},
		{
			op:   map[string]any{"type": "fs.download", "payload": map[string]any{"path": "/srv/archive.bin"}},
			want: []string{"operation: DOWNLOAD FILE", "effect: reads a server file into an approved download snapshot", "path: /srv/archive.bin"},
		},
	}
	for _, tt := range tests {
		b, _ := json.Marshal(tt.op)
		got := tuiDetails(requestRecord{Op: b})
		for _, want := range tt.want {
			if !strings.Contains(got, want) {
				t.Fatalf("details missing %q:\n%s", want, got)
			}
		}
		if strings.Contains(got, "upload_id") {
			t.Fatalf("details expose staging id:\n%s", got)
		}
	}
}

func TestFileTransferRuleCandidatesAndRisk(t *testing.T) {
	api := New(config.Defaults())
	for _, opType := range []string{"fs.upload", "fs.download"} {
		b, _ := json.Marshal(map[string]any{"type": opType, "payload": map[string]any{"path": "/etc/app.bin"}})
		api.reqs[opType] = requestRecord{ID: opType, Op: b}
		got := api.RuleScopeCandidatesForTUI(opType)
		if len(got) != 1 || got[0].OpType != opType || got[0].Pattern != "/etc/app.bin" {
			t.Fatalf("%s candidates=%+v", opType, got)
		}
	}
	upload := rules.Op{Type: "fs.upload", Payload: json.RawMessage(`{"path":"/etc/app.bin"}`)}
	if got := riskFlags(upload); len(got) != 1 || got[0] != "WRITE_ETC" {
		t.Fatalf("upload risk=%v", got)
	}
}

func TestTUIDetailsForConfSetShowsOperationAndEffect(t *testing.T) {
	op := map[string]any{
		"type": "conf.set",
		"payload": map[string]any{
			"path":       "/apps/app/config.yaml",
			"format":     "yaml",
			"key":        "image.tag",
			"value":      "v1.2.3",
			"value_type": "string",
			"create":     true,
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := tuiDetails(requestRecord{Op: b})

	for _, want := range []string{
		"operation: SET CONFIG",
		"effect: updates one structured config key; creates the file with mode 0600 if missing",
		"path: /apps/app/config.yaml",
		"format: yaml",
		"key: image.tag",
		"new: v1.2.3",
		"create_if_missing: true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestTUIDetailsShowsCommandAnalysisAllowBlock(t *testing.T) {
	api := New(config.Defaults())
	api.rules.AddAlways(rules.Rule{ID: "docker-stop-nginx", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"docker", "stop", "nginx"}}})
	api.rules.AddAlways(rules.Rule{ID: "echo", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"echo"}}})

	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-lc", "docker stop nginx && echo ok && rm /"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := api.tuiDetails(requestRecord{Op: b, SessionID: "sess1"})

	for _, want := range []string{
		"command_analysis:",
		"[green]ALLOW[-] docker stop nginx  matched=always:docker-stop-nginx",
		"[green]ALLOW[-] echo ok  matched=always:echo",
		"[red]BLOCK[-] rm /  reason=no matching rule",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestTUIDetailsShowsAllowedCommandWithFdDupRedirect(t *testing.T) {
	api := New(config.Defaults())
	api.rules.AddAlways(rules.Rule{ID: "docker-logs-ipkernel", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"docker", "logs", "--since", "90m", "ipkernel25"}}})

	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"sh", "-c", "docker logs --since 90m ipkernel25 2>&1 | grep -Ea '13:57:4|13:58:4' | tail -120"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := api.tuiDetails(requestRecord{Op: b, SessionID: "sess1"})
	for _, want := range []string{
		"[green]ALLOW[-] docker logs --since 90m ipkernel25  matched=always:docker-logs-ipkernel",
		"[red]BLOCK[-] grep -Ea 13:57:4|13:58:4  reason=no matching rule",
		"[red]BLOCK[-] tail -120  reason=no matching rule",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "reason=redirect") {
		t.Fatalf("details should not block fd dup redirect:\n%s", got)
	}
}

func TestTUIDetailsEscapesCommandAnalysisBrackets(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-lc", `sed -E 's/[0-9]{8}/X/g' && grep -E 'app-(api|web)'`},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := api.tuiDetails(requestRecord{Op: b, SessionID: "sess1"})
	for _, want := range []string{"[0-9[]", "app-(api|web)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing escaped text %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "s/[0-9]{8}/X/g") {
		t.Fatalf("details contains raw dynamic-color tag text:\n%s", got)
	}
}

func TestTUIDetailsShowsUnsupportedSegmentSource(t *testing.T) {
	api := New(config.Defaults())

	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"sh", "-c", "echo redirect-test > /tmp/racg-scope-test.txt"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := api.tuiDetails(requestRecord{Op: b, SessionID: "sess1"})
	if strings.Contains(got, "BLOCK <unknown>") {
		t.Fatalf("details should not show unknown segment:\n%s", got)
	}
	for _, want := range []string{
		"[red]BLOCK[-] echo redirect-test >/tmp/racg-scope-test.txt  reason=redirect",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("details missing %q:\n%s", want, got)
		}
	}
}

func TestRuleScopePatternRejectsShellSeparators(t *testing.T) {
	if _, err := ruleFromScopePattern("docker stop nginx && rm /"); err == nil {
		t.Fatalf("expected separator pattern to be rejected")
	}
	if r, err := ruleFromScopePattern("docker stop n*"); err != nil {
		t.Fatalf("ruleFromScopePattern: %v", err)
	} else if strings.Join(r.Cmd.ArgvPrefix, "\x00") != "docker\x00stop\x00n*" {
		t.Fatalf("argv_prefix=%q", r.Cmd.ArgvPrefix)
	}
}

func TestRuleScopePatternAllowsRegexPipeInsideArg(t *testing.T) {
	r, err := ruleFromScopePattern(`grep -E pavuuk-(main-bot|web-admin|user-runtime)`)
	if err != nil {
		t.Fatalf("ruleFromScopePattern: %v", err)
	}
	if got := strings.Join(r.Cmd.ArgvPrefix, "\x00"); got != "grep\x00-E\x00pavuuk-(main-bot|web-admin|user-runtime)" {
		t.Fatalf("argv_prefix=%q", r.Cmd.ArgvPrefix)
	}
}

func TestRuleScopePatternAllowsQuotedShellOperatorInsideArg(t *testing.T) {
	r, err := ruleFromScopePattern(`docker exec haproxy sh -lc 'printf "show table fe_https\n" | socat - /tmp/haproxy.sock'`)
	if err != nil {
		t.Fatalf("ruleFromScopePattern: %v", err)
	}
	want := []string{"docker", "exec", "haproxy", "sh", "-lc", `printf "show table fe_https\n" | socat - /tmp/haproxy.sock`}
	if strings.Join(r.Cmd.ArgvPrefix, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv_prefix=%q want %q", r.Cmd.ArgvPrefix, want)
	}
}

func TestRuleScopeCandidatesIncludeEachShellSegment(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-lc", "echo second-chain && uname -s && printf done\\n"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1"}

	got := api.RuleScopeCandidatesForTUI("req1")
	if len(got) != 3 {
		t.Fatalf("candidates=%d want 3: %#v", len(got), got)
	}
	want := []string{"echo second-chain", "uname -s", "printf done\\n"}
	for i := range want {
		if got[i].Pattern != want[i] || got[i].Segment != want[i] {
			t.Fatalf("candidate %d=%#v want %q", i, got[i], want[i])
		}
	}
}

func TestRuleScopeAnalysisExplainsUnsupportedDynamicShellWord(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-c", `git config --file /root/realme26-awg.conf Interface.PrivateKey "$(< /etc/amnezia/realme26.key)"`},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1"}

	candidates, problem := api.RuleScopeAnalysisForTUI("req1")
	if len(candidates) != 0 {
		t.Fatalf("candidates=%#v, want none", candidates)
	}
	for _, want := range []string{"dynamic shell word", "git config"} {
		if !strings.Contains(problem, want) {
			t.Fatalf("problem=%q, want %q", problem, want)
		}
	}
}

func TestRuleScopeCandidatesQuoteArgsWithShellOperators(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"docker", "exec", "haproxy", "sh", "-lc", `printf "show table fe_https\n" | socat - /tmp/haproxy.sock`},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1"}

	got := api.RuleScopeCandidatesForTUI("req1")
	if len(got) != 1 {
		t.Fatalf("candidates=%d want 1: %#v", len(got), got)
	}
	want := `docker exec haproxy sh -lc 'printf "show table fe_https\n" | socat - /tmp/haproxy.sock'`
	if got[0].Pattern != want {
		t.Fatalf("pattern=%q want %q", got[0].Pattern, want)
	}
	if got[0].Segment != want {
		t.Fatalf("segment=%q want %q", got[0].Segment, want)
	}
}

func TestRuleScopeCandidatesIncludePathOps(t *testing.T) {
	for _, opType := range []string{
		"fs.read", "fs.patch_unified", "fs.upload", "fs.download",
		"fs.append_block", "fs.replace_literal", "conf.set", "conf.set_kv",
	} {
		t.Run(opType, func(t *testing.T) {
			api := New(config.Defaults())
			op := map[string]any{
				"type": opType,
				"payload": map[string]any{
					"path": "/apps/haproxy/haproxy.cfg",
				},
			}
			b, err := json.Marshal(op)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1", ClientID: "cli"}

			got := api.RuleScopeCandidatesForTUI("req1")
			if len(got) != 1 {
				t.Fatalf("candidates=%d want 1: %#v", len(got), got)
			}
			if got[0].OpType != opType || got[0].Segment != "/apps/haproxy/haproxy.cfg" || got[0].Pattern != "/apps/haproxy/haproxy.cfg" {
				t.Fatalf("candidate=%#v", got[0])
			}
		})
	}
}

func TestDecideWithRulePatternsForTUISavesPathRule(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "fs.read",
		"payload": map[string]any{
			"path": "/apps/haproxy/haproxy.cfg",
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1", ClientID: "cli"}

	err = api.DecideWithRulePatternsForTUI("req1", "ALLOW_SESSION", []string{"/apps/haproxy/haproxy.cfg"})
	if err != nil {
		t.Fatalf("DecideWithRulePatternsForTUI: %v", err)
	}

	rows := api.ListSessionRulesForTUI()
	if len(rows) != 1 {
		t.Fatalf("session rules=%d want 1: %#v", len(rows), rows)
	}
	if rows[0].OpType != "fs.read" {
		t.Fatalf("op_type=%q", rows[0].OpType)
	}
	if rows[0].PathExact == nil || *rows[0].PathExact != "/apps/haproxy/haproxy.cfg" {
		t.Fatalf("path_exact=%v", rows[0].PathExact)
	}
}

func TestDecideWithRulePatternsForTUISavesEachSessionRule(t *testing.T) {
	api := New(config.Defaults())
	op := map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"bash", "-lc", "echo second-chain && uname -s && printf done\\n"},
		},
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	api.reqs["req1"] = requestRecord{ID: "req1", Status: "PENDING_APPROVAL", Op: b, SessionID: "sess1", ClientID: "cli"}

	err = api.DecideWithRulePatternsForTUI("req1", "ALLOW_SESSION", []string{"echo second-chain", "uname -s", "printf done\\n"})
	if err != nil {
		t.Fatalf("DecideWithRulePatternsForTUI: %v", err)
	}

	rows := api.ListSessionRulesForTUI()
	if len(rows) != 3 {
		t.Fatalf("session rules=%d want 3: %#v", len(rows), rows)
	}
	got := map[string]bool{}
	for _, row := range rows {
		if row.CmdArgvJSON != nil {
			got[*row.CmdArgvJSON] = true
		}
	}
	for _, want := range []string{`["echo","second-chain"]`, `["uname","-s"]`, `["printf","done\\n"]`} {
		if !got[want] {
			t.Fatalf("missing rule %s in %#v", want, got)
		}
	}
}

func TestAllowSessionForStdinCommandBindsRuleToHash(t *testing.T) {
	api := New(config.Defaults())
	hash := strings.Repeat("b", 64)
	op, _ := json.Marshal(map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"/bin/bash", "-s"}, "stdin_sha256": hash,
		},
	})
	api.reqs["req-stdin-rule"] = requestRecord{
		ID: "req-stdin-rule", Status: "PENDING_APPROVAL", Op: op, SessionID: "sess", ClientID: "cli",
	}
	if err := api.DecideForTUI("req-stdin-rule", "ALLOW_SESSION"); err != nil {
		t.Fatalf("allow session: %v", err)
	}
	rows := api.ListSessionRulesForTUI()
	if len(rows) != 1 || rows[0].CmdStdinSHA256 == nil || *rows[0].CmdStdinSHA256 != hash {
		t.Fatalf("rows=%+v", rows)
	}
}

func TestAllowSessionOverrideRuleForStdinCommandBindsRuleToHash(t *testing.T) {
	api := New(config.Defaults())
	hash := strings.Repeat("c", 64)
	op, _ := json.Marshal(map[string]any{
		"type": "cmd.run",
		"payload": map[string]any{
			"argv": []string{"/bin/bash", "-s"}, "stdin_sha256": hash,
		},
	})
	api.reqs["req-stdin-override"] = requestRecord{
		ID: "req-stdin-override", Status: "PENDING_APPROVAL", Op: op, SessionID: "sess", ClientID: "cli",
	}
	override := rules.Rule{OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/bash", "-s"}}}
	if err := api.DecideWithRuleForTUI("req-stdin-override", "ALLOW_SESSION", override); err != nil {
		t.Fatalf("allow session: %v", err)
	}
	rows := api.ListSessionRulesForTUI()
	if len(rows) != 1 || rows[0].CmdStdinSHA256 == nil || *rows[0].CmdStdinSHA256 != hash {
		t.Fatalf("rows=%+v", rows)
	}
}
