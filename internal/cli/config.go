package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type ConfigCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewConfigCmd(stdout, stderr io.Writer) *ConfigCmd {
	return &ConfigCmd{stdout: stdout, stderr: stderr}
}

func (c *ConfigCmd) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, configUsage())
		return 2
	}
	switch args[0] {
	case "set":
		return c.runSet(args[1:])
	default:
		fmt.Fprintln(c.stderr, configUsage())
		return 2
	}
}

func (c *ConfigCmd) runSet(args []string) int {
	fs := flag.NewFlagSet("racg config set", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	format := fs.String("format", "", "config format: env, json, yaml")
	valueType := fs.String("type", "string", "value type for json/yaml: string, bool, int, float, null, json")
	backup := fs.Bool("backup", true, "write a backup before editing")
	noBackup := fs.Bool("no-backup", false, "disable backup")
	backupDir := fs.String("backup-dir", "", "directory for backups; default is next to the edited file")
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	noWait := fs.Bool("no-wait", false, "create request and print request id without waiting")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")
	if err := fs.Parse(interspersedConfigSetArgs(args)); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 3 {
		fmt.Fprintln(c.stderr, "usage: racg config set <path> <key> <value> --format <env|json|yaml>")
		return 2
	}
	if strings.TrimSpace(*format) == "" {
		fmt.Fprintln(c.stderr, "format is required")
		return 2
	}
	backupValue := *backup
	if *noBackup {
		backupValue = false
	}

	resolvedHost, resolvedToken, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}

	payload := map[string]any{
		"path":       rest[0],
		"format":     strings.TrimSpace(*format),
		"key":        rest[1],
		"value":      rest[2],
		"value_type": strings.TrimSpace(*valueType),
		"backup":     backupValue,
	}
	if strings.TrimSpace(*backupDir) != "" {
		payload["backup_dir"] = strings.TrimSpace(*backupDir)
	}
	created, err := client.createRequest(map[string]any{
		"op": map[string]any{
			"type":    "conf.set",
			"payload": payload,
		},
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "config set request failed: %v\n", err)
		return 1
	}
	if *noWait {
		fmt.Fprintf(c.stdout, "request_id: %s\nstatus: %s\n", created.RequestID, created.Status)
		return 0
	}
	rec, err := client.waitRequest(created.RequestID, *pollInterval, *waitTimeout)
	if err != nil {
		fmt.Fprintf(c.stderr, "config set wait failed: %v\n", err)
		return 1
	}
	printRequestResult(c.stdout, rec)
	if rec.Status == "SUCCEEDED" && rec.Result != nil {
		return normalizeExitCode(rec.Result.ExitCode)
	}
	return 1
}

func interspersedConfigSetArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--format":        true,
		"--type":          true,
		"--backup-dir":    true,
		"--host":          true,
		"--token":         true,
		"--name":          true,
		"--poll-interval": true,
		"--wait-timeout":  true,
	}
	boolFlags := map[string]bool{
		"--backup":    true,
		"--no-backup": true,
		"--no-wait":   true,
	}
	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			if eq := strings.IndexByte(arg, '='); eq > 0 {
				name := arg[:eq]
				if valueFlags[name] || boolFlags[name] {
					flags = append(flags, arg)
					continue
				}
			}
			if valueFlags[arg] && i+1 < len(args) {
				flags = append(flags, arg, args[i+1])
				i++
				continue
			}
			if boolFlags[arg] {
				flags = append(flags, arg)
				continue
			}
		}
		positional = append(positional, arg)
	}
	return append(flags, positional...)
}

func configUsage() string {
	return `usage: racg config <set> [args]

Set structured config values through RACG approval:
  racg config set /app/.env PORT 8080 --format env
  racg config set /app/config.json server.debug true --format json --type bool
  racg config set /app/values.yaml image.tag v1.2.3 --format yaml

Supported formats:
  env
  json
  yaml

Supported value types for json/yaml:
  string
  bool
  int
  float
  null
  json

Backups are enabled by default:
  <file>.racg-backup-YYYYMMDDTHHMMSSZ

Common flags:
  --format env|json|yaml
  --type string|bool|int|float|null|json
  --no-backup
  --backup-dir DIR
  --host URL
  --token TOKEN
  --no-wait
`
}
