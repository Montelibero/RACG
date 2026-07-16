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
	case "use":
		return NewAuthCmd(r.stdout, r.stderr).RunUse(rest[1:])
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
  file       read, patch, upload, or download files through approval
  config     set env/json/yaml config keys through approval
  rules      list, enable/disable/delete, and install presets
  sessions   inspect persisted audit sessions
  update     update racg from GitHub Releases

quick start:
  sudo racg serve -listen-addr 127.0.0.1 -port 8777
  sudo racg serve --profile docker -listen-addr 127.0.0.1 -port 8777
  racg login --host server --pairing-code ABC123
  export RACG_CLIENT_NAME=server

common commands:
  racg run -- bash -lc 'date && uname -a'
  racg run --name prod -- bash -lc 'date && uname -a'
  racg run --no-wait -- /bin/sh -c 'while true; do date; sleep 3; done'
  racg request logs <id> --live
  racg request tail <id>
  racg request cancel <id>

file helpers:
  racg file read /path/file.txt
  racg file read /path/file.txt --max-bytes 65536
  racg file patch /path/file.txt --diff-file /tmp/change.patch
  racg file patch /path/file.txt --diff '@@ -1 +1 @@...'
  racg file upload ./local.bin /srv/remote.bin
  racg file upload ./secret.bin /srv/secret.bin --mode 0600
  racg file download /srv/remote.bin ./local.bin
  racg file download /srv/remote.bin ./local.bin --force

config helpers:
  racg config set /app/.env PORT 8080 --format env
  racg config set values.yaml image.tag v1.2.3 --format yaml
  racg config set config.json server.debug true --format json --type bool
  racg config set /etc/netplan/60-static.yaml network '{"version":2}' --format yaml --type json --create

auth:
  most client commands accept --name, --host and --token, or use
  RACG_CLIENT_NAME/RACG_HOST/RACG_TOKEN.
  client profiles are stored in ~/.config/racg/clients/.
  login --host server saves profile "server"; --name overrides the profile name.
  without --name, RACG_CLIENT_NAME, or --host+--token, client commands fail
  instead of reading global mutable state.
  server rules/history are stored in ~/.local/state/racg/racg.db by default;
  use serve --profile <name> for separate server rule/history sets.
`
}
