package httpapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

func TestListJobsForTUI(t *testing.T) {
	api := &API{reqs: map[string]requestRecord{
		"r1": {ID: "r1", Status: "RUNNING", CreatedAt: "2026-02-11T01:00:00Z"},
		"r2": {ID: "r2", Status: "APPROVED", CreatedAt: "2026-02-11T01:01:00Z"},
		"r3": {ID: "r3", Status: "SUCCEEDED", CreatedAt: "2026-02-11T01:02:00Z"},
		"r4": {ID: "r4", Status: "FAILED", CreatedAt: "2026-02-11T01:03:00Z"},
		"r5": {ID: "r5", Status: "DENIED", CreatedAt: "2026-02-11T01:04:00Z"},
		"r6": {ID: "r6", Status: "CANCELED", CreatedAt: "2026-02-11T01:05:00Z"},
	}}

	runningOnly := api.ListJobsForTUI(false)
	if len(runningOnly) != 2 {
		t.Fatalf("runningOnly len=%d, want 2", len(runningOnly))
	}
	if runningOnly[0].ID != "r2" || runningOnly[1].ID != "r1" {
		t.Fatalf("runningOnly ids=%v,%v", runningOnly[0].ID, runningOnly[1].ID)
	}

	all := api.ListJobsForTUI(true)
	if len(all) != 6 {
		t.Fatalf("all len=%d, want 6", len(all))
	}
	if all[0].ID != "r6" || all[1].ID != "r5" || all[2].ID != "r4" || all[3].ID != "r3" || all[4].ID != "r2" || all[5].ID != "r1" {
		t.Fatalf("unexpected order/ids: %#v", all)
	}
}

func TestListSessionRulesForTUI(t *testing.T) {
	api := New(config.Defaults())
	api.rules.AddSession("sess1", rules.Rule{
		ID:     "rule1",
		OpType: "cmd.run",
		Cmd:    &rules.CmdRule{ArgvPrefix: []string{"git", "status"}},
	})

	rows := api.ListSessionRulesForTUI()
	if len(rows) != 1 {
		t.Fatalf("rows len=%d, want 1", len(rows))
	}
	if rows[0].RuleID != "rule1" || rows[0].Source != "session:sess1" || rows[0].OpType != "cmd.run" || !rows[0].Enabled {
		t.Fatalf("row=%#v", rows[0])
	}
	if rows[0].CmdArgvJSON == nil || *rows[0].CmdArgvJSON != `["git","status"]` {
		t.Fatalf("cmd json=%v", rows[0].CmdArgvJSON)
	}
}

func TestAddManualAlwaysCommandRuleForTUI(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	api := New(config.Defaults(), WithStore(st))

	ruleID, err := api.AddManualRuleForTUI(ManualRuleInput{
		Source: "always", OpType: "cmd.run", Match: "command", Pattern: "docker logs *",
	})
	if err != nil {
		t.Fatalf("add manual always rule: %v", err)
	}
	if strings.TrimSpace(ruleID) == "" {
		t.Fatal("empty rule id")
	}
	op := rules.Op{Type: "cmd.run", Payload: json.RawMessage(`{"argv":["docker","logs","nginx","--tail","20"]}`)}
	match, ok := api.rules.Match("any-session", op)
	if !ok || match.Source != "always" || match.RuleID != ruleID {
		t.Fatalf("match=%+v ok=%t", match, ok)
	}
	rows, err := st.ListRules(context.Background(), 10)
	if err != nil || len(rows) != 1 || rows[0].RuleID != ruleID || rows[0].Source != "always" {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
}

func TestAddManualAlwaysRuleForTUIRejectsDangerousRuleByDefault(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	api := New(config.Defaults(), WithStore(st))

	tests := []ManualRuleInput{
		{Source: "always", OpType: "cmd.run", Match: "command", Pattern: "rm -rf /"},
		{Source: "always", OpType: "cmd.run", Match: "command", Pattern: "/usr/bin/rm -rf /"},
		{Source: "always", OpType: "cmd.run", Match: "command", Pattern: "/usr/sbin/iptables -F"},
		{Source: "always", OpType: "cmd.run", Match: "command", Pattern: "/usr/bin/systemctl stop sshd"},
		{Source: "always", OpType: "cmd.run", Match: "command", Pattern: "sudo rm -rf /"},
		{Source: "always", OpType: "cmd.run", Match: "command", Pattern: "sh -c 'rm -rf /'"},
		{Source: "always", OpType: "cmd.run", Match: "command", Pattern: "*"},
		{Source: "always", OpType: "fs.patch_unified", Match: "exact", Pattern: "/etc/hosts"},
		{Source: "always", OpType: "fs.upload", Match: "prefix", Pattern: "/"},
	}
	for _, input := range tests {
		if _, err := api.AddManualRuleForTUI(input); err == nil || err.Error() != "ALLOW_ALWAYS_NOT_PERMITTED" {
			t.Fatalf("input=%+v err=%v, want ALLOW_ALWAYS_NOT_PERMITTED", input, err)
		}
	}
}

func TestAddManualAlwaysRuleForTUIAllowsDangerousRuleWhenConfigured(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := config.Defaults()
	cfg.AllowAlwaysForDangerous = true
	api := New(cfg, WithStore(st))

	if _, err := api.AddManualRuleForTUI(ManualRuleInput{
		Source: "always", OpType: "cmd.run", Match: "command", Pattern: "rm -rf /",
	}); err != nil {
		t.Fatalf("add dangerous manual always rule: %v", err)
	}
}

func TestAddManualSessionPathRuleForTUI(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := st.InsertSession(context.Background(), store.Session{ID: "sess-1", StartedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	api := New(config.Defaults(), WithStore(st))

	ruleID, err := api.AddManualRuleForTUI(ManualRuleInput{
		Source: "session", SessionID: "sess-1", OpType: "fs.read", Match: "glob", Pattern: "/srv/*.conf",
	})
	if err != nil {
		t.Fatalf("add manual session rule: %v", err)
	}
	op := rules.Op{Type: "fs.read", Payload: json.RawMessage(`{"path":"/srv/app.conf"}`)}
	match, ok := api.rules.Match("sess-1", op)
	if !ok || match.Source != "session" || match.RuleID != ruleID {
		t.Fatalf("match=%+v ok=%t", match, ok)
	}
	if _, ok := api.rules.Match("sess-2", op); ok {
		t.Fatal("session rule matched another session")
	}
	rows, err := st.ListRules(context.Background(), 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("session rule persisted rows=%+v err=%v", rows, err)
	}
}

func TestAddManualRuleForTUIRejectsUnsafeOrInvalidInput(t *testing.T) {
	api := New(config.Defaults())
	tests := []ManualRuleInput{
		{Source: "always", OpType: "cmd.run", Match: "command", Pattern: "docker logs nginx && rm -rf /"},
		{Source: "session", OpType: "cmd.run", Match: "command", Pattern: "git status"},
		{Source: "always", OpType: "svc.restart", Match: "exact", Pattern: "nginx"},
		{Source: "always", OpType: "fs.read", Match: "command", Pattern: "/etc/hosts"},
	}
	for _, input := range tests {
		if _, err := api.AddManualRuleForTUI(input); err == nil {
			t.Fatalf("input unexpectedly accepted: %+v", input)
		}
	}
}

func TestListManualRuleSessionsForTUIIncludesClientIdentity(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	started := time.Date(2026, 8, 26, 18, 30, 0, 0, time.UTC)
	if err := st.InsertSession(context.Background(), store.Session{ID: "12345678-1234-1234-1234-123456789abc", StartedAt: started}); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	api := New(config.Defaults(), WithStore(st))
	api.reqs["req-1"] = requestRecord{SessionID: "12345678-1234-1234-1234-123456789abc", ClientID: "deploy-agent"}

	got, err := api.ListManualRuleSessionsForTUI()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(got) != 1 || got[0].ID != "12345678-1234-1234-1234-123456789abc" || got[0].ClientID != "deploy-agent" || !got[0].StartedAt.Equal(started) {
		t.Fatalf("sessions=%+v", got)
	}
}

func TestDisableAndEnableAlwaysRuleForTUIUpdatesLiveEngine(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	api := New(config.Defaults(), WithStore(st))
	ruleID, err := api.AddManualRuleForTUI(ManualRuleInput{
		Source: "always", OpType: "cmd.run", Match: "command", Pattern: "git status",
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	op := rules.Op{Type: "cmd.run", Payload: json.RawMessage(`{"argv":["git","status"]}`)}
	if _, ok := api.rules.Match("sess", op); !ok {
		t.Fatal("new rule did not match")
	}
	if err := api.SetAlwaysRuleEnabledForTUI(ruleID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, ok := api.rules.Match("sess", op); ok {
		t.Fatal("disabled rule still matched live engine")
	}
	if err := api.SetAlwaysRuleEnabledForTUI(ruleID, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, ok := api.rules.Match("sess", op); !ok {
		t.Fatal("re-enabled rule did not match live engine")
	}
}

func TestDeleteSessionRuleForTUIUpdatesLiveEngine(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := st.InsertSession(context.Background(), store.Session{ID: "sess-1", StartedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	api := New(config.Defaults(), WithStore(st))
	ruleID, err := api.AddManualRuleForTUI(ManualRuleInput{
		Source: "session", SessionID: "sess-1", OpType: "cmd.run", Match: "command", Pattern: "git status",
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	if err := api.DeleteRuleForTUI("session:sess-1", ruleID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	op := rules.Op{Type: "cmd.run", Payload: json.RawMessage(`{"argv":["git","status"]}`)}
	if _, ok := api.rules.Match("sess-1", op); ok {
		t.Fatal("deleted session rule still matched live engine")
	}
}
