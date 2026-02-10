package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/version"
)

type Root struct {
	stdout io.Writer
	stderr io.Writer
}

func NewRoot(stdout, stderr io.Writer) *Root {
	return &Root{stdout: stdout, stderr: stderr}
}

// Run executes the CLI and returns an exit code.
func (r *Root) Run(args []string) int {
	fs := flag.NewFlagSet("racg", flag.ContinueOnError)
	fs.SetOutput(r.stderr)

	showVersion := fs.Bool("version", false, "print version")
	fs.BoolVar(showVersion, "v", false, "print version")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(r.stdout, version.Version)
		return 0
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(r.stderr, usage())
		return 2
	}

	switch rest[0] {
	case "serve":
		return NewServeCmd(r.stdout, r.stderr).Run(rest[1:])
	case "rules":
		return NewRulesCmd(r.stdout, r.stderr, config.Defaults().DBPath).Run(rest[1:])
	case "sessions":
		return NewSessionsCmd(r.stdout, r.stderr, config.Defaults().DBPath).Run(rest[1:])
	default:
		fmt.Fprintln(r.stderr, usage())
		return 2
	}
}

func usage() string {
	return "usage: racg [--version] <command>\n\ncommands:\n  serve\n  rules\n  sessions\n"
}
