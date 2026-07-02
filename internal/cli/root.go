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
	showHelp := fs.Bool("help", false, "print help")
	fs.BoolVar(showHelp, "h", false, "print help")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showHelp {
		fmt.Fprintln(r.stdout, usage())
		return 0
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
	case "login":
		return NewAuthCmd(r.stdout, r.stderr).RunLogin(rest[1:])
	case "logout":
		return NewAuthCmd(r.stdout, r.stderr).RunLogout(rest[1:])
	case "session":
		return NewAuthCmd(r.stdout, r.stderr).RunSession(rest[1:])
	case "run":
		return NewRequestCmd(r.stdout, r.stderr).RunRun(rest[1:])
	case "request":
		return NewRequestCmd(r.stdout, r.stderr).Run(rest[1:])
	case "rules":
		return NewRulesCmd(r.stdout, r.stderr, config.Defaults().DBPath).Run(rest[1:])
	case "sessions":
		return NewSessionsCmd(r.stdout, r.stderr, config.Defaults().DBPath).Run(rest[1:])
	case "update":
		return NewUpdateCmd(r.stdout, r.stderr).Run(rest[1:])
	case "config":
		return NewConfigCmd(r.stdout, r.stderr).Run(rest[1:])
	case "file":
		return NewFileCmd(r.stdout, r.stderr).Run(rest[1:])
	default:
		fmt.Fprintln(r.stderr, usage())
		return 2
	}
}

func usage() string {
	return `usage: racg [--version] <command>

commands:
  serve      start RACG server and TUI
  login      save client auth from a pairing code
  logout     remove saved client auth
  session    inspect saved/current session
  run        submit cmd.run and wait by default
  request    cancel, tail, or read request logs
  file       read or patch plain text files through approval
  config     set env/json/yaml config keys through approval
  rules      list, enable/disable/delete, and install presets
  sessions   inspect persisted audit sessions
  update     update racg from GitHub Releases

quick start:
  sudo racg serve -listen-addr 127.0.0.1 -port 8777
  racg login --host http://127.0.0.1:8777 --pairing-code ABC123

common commands:
  racg run -- bash -lc 'date && uname -a'
  racg run --no-wait -- /bin/sh -c 'while true; do date; sleep 3; done'
  racg request logs <id> --live
  racg request tail <id>
  racg request cancel <id>

file helpers:
  racg file read /path/file.txt
  racg file read /path/file.txt --max-bytes 65536
  racg file patch /path/file.txt --diff-file /tmp/change.patch
  racg file patch /path/file.txt --diff '@@ -1 +1 @@...'

config helpers:
  racg config set /app/.env PORT 8080 --format env
  racg config set values.yaml image.tag v1.2.3 --format yaml
  racg config set config.json server.debug true --format json --type bool

auth:
  most client commands accept --host and --token, or use RACG_HOST/RACG_TOKEN,
  or use saved auth from racg login.
`
}
