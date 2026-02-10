package cli

import (
	"flag"
	"fmt"
	"io"

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

	fmt.Fprintln(r.stderr, "usage: racg [--version] <command>")
	return 2
}
