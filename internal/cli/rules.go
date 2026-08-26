package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

type RulesCmd struct {
	stdout io.Writer
	stderr io.Writer
	dbPath string
}

func NewRulesCmd(stdout, stderr io.Writer, defaultDBPath string) *RulesCmd {
	return &RulesCmd{stdout: stdout, stderr: stderr, dbPath: defaultDBPath}
}

func (c *RulesCmd) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg rules <list|disable> [args]")
		return 2
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("racg rules list", flag.ContinueOnError)
		fs.SetOutput(c.stderr)
		db := fs.String("db", c.dbPath, "sqlite db path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		return c.runList(*db)
	case "disable":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintln(c.stderr, "usage: racg rules disable <rule_id> [--db PATH]")
			return 2
		}
		ruleID := strings.TrimSpace(args[1])

		fs := flag.NewFlagSet("racg rules disable", flag.ContinueOnError)
		fs.SetOutput(c.stderr)
		db := fs.String("db", c.dbPath, "sqlite db path")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		return c.runDisable(*db, ruleID)
	case "presets":
		return c.runPresets(args[1:])
	default:
		fmt.Fprintln(c.stderr, "usage: racg rules <list|disable|presets> [args]")
		return 2
	}
}

func (c *RulesCmd) runPresets(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg rules presets <list|install> [args]")
		return 2
	}

	switch args[0] {
	case "list":
		for _, p := range rulePresets() {
			fmt.Fprintf(c.stdout, "%s\t%s\trules=%d\n", p.Name, p.Description, len(p.Rules))
		}
		return 0
	case "install":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintln(c.stderr, "usage: racg rules presets install <preset_name> [--db PATH]")
			return 2
		}
		name := strings.TrimSpace(args[1])
		fs := flag.NewFlagSet("racg rules presets install", flag.ContinueOnError)
		fs.SetOutput(c.stderr)
		db := fs.String("db", c.dbPath, "sqlite db path")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		return c.runPresetInstall(*db, name)
	default:
		fmt.Fprintln(c.stderr, "usage: racg rules presets <list|install> [args]")
		return 2
	}
}

func (c *RulesCmd) runList(dbPath string) int {
	ctx := context.Background()

	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(c.stderr, "db open failed: %v\n", err)
		return 1
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		fmt.Fprintf(c.stderr, "db migrate failed: %v\n", err)
		return 1
	}

	rs, err := st.LoadEnabledAlwaysRules(ctx)
	if err != nil {
		fmt.Fprintf(c.stderr, "db query failed: %v\n", err)
		return 1
	}

	for _, r := range rs {
		fmt.Fprintln(c.stdout, formatRule(r))
	}
	return 0
}

func (c *RulesCmd) runDisable(dbPath string, ruleID string) int {
	ctx := context.Background()

	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(c.stderr, "db open failed: %v\n", err)
		return 1
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		fmt.Fprintf(c.stderr, "db migrate failed: %v\n", err)
		return 1
	}

	if err := st.DisableRule(ctx, ruleID, time.Now().UTC()); err != nil {
		fmt.Fprintf(c.stderr, "disable failed: %v\n", err)
		return 1
	}
	return 0
}

func (c *RulesCmd) runPresetInstall(dbPath string, name string) int {
	ctx := context.Background()

	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(c.stderr, "db open failed: %v\n", err)
		return 1
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		fmt.Fprintf(c.stderr, "db migrate failed: %v\n", err)
		return 1
	}

	installed, skipped, err := installRulePreset(ctx, st, name)
	if err != nil {
		fmt.Fprintf(c.stderr, "preset install failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "preset=%s installed=%d skipped=%d\n", name, installed, skipped)
	return 0
}

type rulePreset struct {
	Name        string
	Description string
	Rules       []rules.Rule
}

func rulePresets() []rulePreset {
	return []rulePreset{
		{
			Name:        "readonly-diagnostics",
			Description: "read-only git, kubectl, and health-check diagnostics",
			Rules: []rules.Rule{
				cmdPresetRule("readonly-diagnostics", "git-status", []string{"git", "status"}),
				cmdPresetRule("readonly-diagnostics", "git-log", []string{"git", "log"}),
				cmdPresetRule("readonly-diagnostics", "kubectl-get", []string{"kubectl", "get"}),
				cmdPresetRule("readonly-diagnostics", "kubectl-describe", []string{"kubectl", "describe"}),
				cmdPresetRule("readonly-diagnostics", "kubectl-logs", []string{"kubectl", "logs"}),
				cmdPresetRule("readonly-diagnostics", "curl-health", []string{"curl", "*health*"}),
			},
		},
	}
}

func cmdPresetRule(presetName, ruleName string, argvPrefix []string) rules.Rule {
	return rules.Rule{
		ID:     "preset:" + presetName + ":" + ruleName,
		OpType: "cmd.run",
		Cmd:    &rules.CmdRule{ArgvPrefix: argvPrefix},
	}
}

func installRulePreset(ctx context.Context, st *store.Store, name string) (installed int, skipped int, err error) {
	var preset *rulePreset
	for _, p := range rulePresets() {
		if p.Name == name {
			cp := p
			preset = &cp
			break
		}
	}
	if preset == nil {
		return 0, 0, fmt.Errorf("unknown preset %q", name)
	}

	existingRows, err := st.ListRules(ctx, 10000)
	if err != nil {
		return 0, 0, err
	}
	existing := map[string]store.RuleRow{}
	for _, row := range existingRows {
		existing[row.RuleID] = row
	}

	now := time.Now().UTC()
	for _, r := range preset.Rules {
		if row, ok := existing[r.ID]; ok {
			if !row.Enabled {
				if err := st.EnableRule(ctx, r.ID); err != nil {
					return installed, skipped, err
				}
				installed++
			} else {
				skipped++
			}
			continue
		}
		if err := st.InsertAlwaysRule(ctx, r, now); err != nil {
			return installed, skipped, err
		}
		installed++
	}
	return installed, skipped, nil
}

func formatRule(r rules.Rule) string {
	switch r.OpType {
	case "cmd.run":
		if r.Cmd != nil && len(r.Cmd.ArgvPrefix) > 0 {
			formatted := fmt.Sprintf("%s\tcmd.run\targv_prefix=%q", r.ID, strings.Join(r.Cmd.ArgvPrefix, " "))
			if r.Cmd.StdinSHA256 != "" {
				formatted += "\tstdin_sha256=" + r.Cmd.StdinSHA256
			}
			return formatted
		}
		return fmt.Sprintf("%s\tcmd.run", r.ID)
	default:
		if r.Path != nil {
			if r.Path.Exact != "" {
				return fmt.Sprintf("%s\t%s\tpath_exact=%q", r.ID, r.OpType, r.Path.Exact)
			}
			if r.Path.Prefix != "" {
				return fmt.Sprintf("%s\t%s\tpath_prefix=%q", r.ID, r.OpType, r.Path.Prefix)
			}
			if r.Path.Glob != "" {
				return fmt.Sprintf("%s\t%s\tpath_glob=%q", r.ID, r.OpType, r.Path.Glob)
			}
		}
		return fmt.Sprintf("%s\t%s", r.ID, r.OpType)
	}
}
