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
	default:
		fmt.Fprintln(c.stderr, "usage: racg rules <list|disable> [args]")
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

func formatRule(r rules.Rule) string {
	switch r.OpType {
	case "cmd.run":
		if r.Cmd != nil && len(r.Cmd.ArgvPrefix) > 0 {
			return fmt.Sprintf("%s\tcmd.run\targv_prefix=%q", r.ID, strings.Join(r.Cmd.ArgvPrefix, " "))
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

