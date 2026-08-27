package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/rules"
)

func TestAlwaysRulesCRUD(t *testing.T) {
	ctx := context.Background()

	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	now := time.Now().UTC()
	r := rules.Rule{
		ID:     "r1",
		OpType: "cmd.run",
		Cmd:    &rules.CmdRule{ArgvPrefix: []string{"/bin/echo", "hi"}},
	}
	if err := s.InsertAlwaysRule(ctx, r, now); err != nil {
		t.Fatalf("InsertAlwaysRule: %v", err)
	}

	enabled, err := s.LoadEnabledAlwaysRules(ctx)
	if err != nil {
		t.Fatalf("LoadEnabledAlwaysRules: %v", err)
	}
	if got := len(enabled); got != 1 {
		t.Fatalf("enabled len=%d", got)
	}
	if enabled[0].ID != "r1" {
		t.Fatalf("rule id=%q", enabled[0].ID)
	}

	if err := s.DisableRule(ctx, "r1", now.Add(time.Second)); err != nil {
		t.Fatalf("DisableRule: %v", err)
	}

	enabled2, err := s.LoadEnabledAlwaysRules(ctx)
	if err != nil {
		t.Fatalf("LoadEnabledAlwaysRules2: %v", err)
	}
	if got := len(enabled2); got != 0 {
		t.Fatalf("enabled2 len=%d", got)
	}
}

func TestAlwaysRuleDoesNotPersistStdinHash(t *testing.T) {
	ctx := context.Background()
	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	r := rules.Rule{ID: "script", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/bash", "-s"}}}
	if err := s.InsertAlwaysRule(ctx, r, time.Now().UTC()); err != nil {
		t.Fatalf("InsertAlwaysRule: %v", err)
	}
	loaded, err := s.LoadEnabledAlwaysRules(ctx)
	if err != nil {
		t.Fatalf("LoadEnabledAlwaysRules: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Cmd == nil {
		t.Fatalf("loaded=%+v", loaded)
	}
	var hash sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT cmd_stdin_sha256 FROM rules WHERE rule_id = ?`, "script").Scan(&hash); err != nil {
		t.Fatalf("query hash: %v", err)
	}
	if hash.Valid {
		t.Fatalf("stored legacy stdin hash %q", hash.String)
	}
}

func TestMigrationClearsLegacyRuleStdinHashes(t *testing.T) {
	ctx := context.Background()
	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO rules(rule_id, source, op_type, cmd_argv_prefix_json, cmd_stdin_sha256, enabled, created_at) VALUES(?, ?, ?, ?, ?, 1, ?)`,
		"legacy", "always", "cmd.run", `["/bin/bash","-s"]`, "abc123", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert legacy rule: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 5`); err != nil {
		t.Fatalf("reset migration: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("rerun migration: %v", err)
	}
	var hash sql.NullString
	var enabled int
	var disabledAt sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT cmd_stdin_sha256, enabled, disabled_at FROM rules WHERE rule_id = ?`, "legacy").Scan(&hash, &enabled, &disabledAt); err != nil {
		t.Fatalf("query hash: %v", err)
	}
	if hash.Valid {
		t.Fatalf("legacy stdin hash was not cleared: %q", hash.String)
	}
	if enabled != 0 || !disabledAt.Valid {
		t.Fatalf("legacy rule enabled=%d disabled_at=%q", enabled, disabledAt.String)
	}
	loaded, err := s.LoadEnabledAlwaysRules(ctx)
	if err != nil {
		t.Fatalf("LoadEnabledAlwaysRules: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("loaded disabled legacy rules: %+v", loaded)
	}
}

func TestListRulesIncludesDisabled(t *testing.T) {
	ctx := context.Background()

	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	now := time.Now().UTC()
	r := rules.Rule{
		ID:     "r1",
		OpType: "cmd.run",
		Cmd:    &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}},
	}
	if err := s.InsertAlwaysRule(ctx, r, now); err != nil {
		t.Fatalf("InsertAlwaysRule: %v", err)
	}
	if err := s.DisableRule(ctx, "r1", now.Add(time.Second)); err != nil {
		t.Fatalf("DisableRule: %v", err)
	}

	rs, err := s.ListRules(ctx, 100)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("len=%d", len(rs))
	}
	if rs[0].RuleID != "r1" {
		t.Fatalf("RuleID=%q", rs[0].RuleID)
	}
	if rs[0].Enabled {
		t.Fatalf("expected disabled")
	}
	if rs[0].DisabledAt == nil {
		t.Fatalf("expected DisabledAt set")
	}
}

func TestEnableAndDeleteRule(t *testing.T) {
	ctx := context.Background()

	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	now := time.Now().UTC()
	r := rules.Rule{
		ID:     "r1",
		OpType: "cmd.run",
		Cmd:    &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}},
	}
	if err := s.InsertAlwaysRule(ctx, r, now); err != nil {
		t.Fatalf("InsertAlwaysRule: %v", err)
	}
	if err := s.DisableRule(ctx, "r1", now.Add(time.Second)); err != nil {
		t.Fatalf("DisableRule: %v", err)
	}
	if err := s.EnableRule(ctx, "r1"); err != nil {
		t.Fatalf("EnableRule: %v", err)
	}

	enabled, err := s.LoadEnabledAlwaysRules(ctx)
	if err != nil {
		t.Fatalf("LoadEnabledAlwaysRules: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("enabled len=%d", len(enabled))
	}

	if err := s.DeleteRule(ctx, "r1"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	rs, err := s.ListRules(ctx, 100)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rs) != 0 {
		t.Fatalf("len=%d", len(rs))
	}
}
