package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/store"
)

type SessionsCmd struct {
	stdout io.Writer
	stderr io.Writer
	dbPath string
}

func NewSessionsCmd(stdout, stderr io.Writer, defaultDBPath string) *SessionsCmd {
	return &SessionsCmd{stdout: stdout, stderr: stderr, dbPath: defaultDBPath}
}

func (c *SessionsCmd) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg sessions <list|show> [args]")
		return 2
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("racg sessions list", flag.ContinueOnError)
		fs.SetOutput(c.stderr)
		db := fs.String("db", c.dbPath, "sqlite db path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		return c.runList(*db)
	case "show":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintln(c.stderr, "usage: racg sessions show <session_id> [--db PATH]")
			return 2
		}
		fs := flag.NewFlagSet("racg sessions show", flag.ContinueOnError)
		fs.SetOutput(c.stderr)
		db := fs.String("db", c.dbPath, "sqlite db path")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		return c.runShow(*db, strings.TrimSpace(args[1]))
	default:
		fmt.Fprintln(c.stderr, "usage: racg sessions <list|show> [args]")
		return 2
	}
}

func (c *SessionsCmd) runList(dbPath string) int {
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

	ss, err := st.ListSessions(ctx, 100)
	if err != nil {
		fmt.Fprintf(c.stderr, "db query failed: %v\n", err)
		return 1
	}
	for _, s := range ss {
		ended := ""
		if s.EndedAt != nil {
			ended = s.EndedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		fmt.Fprintf(c.stdout, "%s\t%s\t%s\n", s.ID, s.StartedAt.UTC().Format("2006-01-02T15:04:05Z"), ended)
	}
	return 0
}

func (c *SessionsCmd) runShow(dbPath string, sessionID string) int {
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

	sess, err := st.GetSession(ctx, sessionID)
	if err != nil {
		fmt.Fprintf(c.stderr, "session not found: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "session_id=%s\n", sess.ID)
	fmt.Fprintf(c.stdout, "started_at=%s\n", sess.StartedAt.UTC().Format(time.RFC3339Nano))
	if sess.EndedAt != nil {
		fmt.Fprintf(c.stdout, "ended_at=%s\n", sess.EndedAt.UTC().Format(time.RFC3339Nano))
	} else {
		fmt.Fprintf(c.stdout, "ended_at=\n")
	}
	return 0
}
