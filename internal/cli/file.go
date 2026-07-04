package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type FileCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewFileCmd(stdout, stderr io.Writer) *FileCmd {
	return &FileCmd{stdout: stdout, stderr: stderr}
}

func (c *FileCmd) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, fileUsage())
		return 2
	}
	switch args[0] {
	case "read":
		return c.runRead(args[1:])
	case "patch":
		return c.runPatch(args[1:])
	default:
		fmt.Fprintln(c.stderr, fileUsage())
		return 2
	}
}

func (c *FileCmd) runRead(args []string) int {
	fs := flag.NewFlagSet("racg file read", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	maxBytes := fs.Int("max-bytes", 0, "maximum bytes to read")
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	noWait := fs.Bool("no-wait", false, "create request and print request id without waiting")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")
	if err := fs.Parse(interspersedFileArgs(args)); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(c.stderr, "usage: racg file read <path> [--max-bytes N]")
		return 2
	}

	payload := map[string]any{"path": rest[0]}
	if *maxBytes > 0 {
		payload["max_bytes"] = *maxBytes
	}
	return c.submitFileRequest(*host, *token, *name, *noWait, *pollInterval, *waitTimeout, "fs.read", payload)
}

func (c *FileCmd) runPatch(args []string) int {
	fs := flag.NewFlagSet("racg file patch", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	diff := fs.String("diff", "", "unified diff text")
	diffFile := fs.String("diff-file", "", "path to a unified diff file")
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	noWait := fs.Bool("no-wait", false, "create request and print request id without waiting")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")
	if err := fs.Parse(interspersedFileArgs(args)); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(c.stderr, "usage: racg file patch <path> (--diff TEXT | --diff-file PATH)")
		return 2
	}
	diffText := *diff
	if strings.TrimSpace(*diffFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(*diffFile))
		if err != nil {
			fmt.Fprintf(c.stderr, "read diff file failed: %v\n", err)
			return 1
		}
		diffText = string(b)
	}
	if diffText == "" {
		fmt.Fprintln(c.stderr, "diff is required; pass --diff or --diff-file")
		return 2
	}

	payload := map[string]any{"path": rest[0], "diff": diffText}
	return c.submitFileRequest(*host, *token, *name, *noWait, *pollInterval, *waitTimeout, "fs.patch_unified", payload)
}

func (c *FileCmd) submitFileRequest(host, token, name string, noWait bool, pollInterval, waitTimeout time.Duration, opType string, payload map[string]any) int {
	resolvedHost, resolvedToken, err := resolveClientAuthNamed(host, token, name)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	created, err := client.createRequest(map[string]any{
		"op": map[string]any{
			"type":    opType,
			"payload": payload,
		},
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "file request failed: %v\n", err)
		return 1
	}
	if noWait {
		fmt.Fprintf(c.stdout, "request_id: %s\nstatus: %s\n", created.RequestID, created.Status)
		return 0
	}
	rec, err := client.waitRequest(created.RequestID, pollInterval, waitTimeout)
	if err != nil {
		fmt.Fprintf(c.stderr, "file request wait failed: %v\n", err)
		return 1
	}
	printRequestResult(c.stdout, rec)
	if rec.Status == "SUCCEEDED" && rec.Result != nil {
		return normalizeExitCode(rec.Result.ExitCode)
	}
	return 1
}

func interspersedFileArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--max-bytes":     true,
		"--diff":          true,
		"--diff-file":     true,
		"--host":          true,
		"--token":         true,
		"--name":          true,
		"--poll-interval": true,
		"--wait-timeout":  true,
	}
	boolFlags := map[string]bool{
		"--no-wait": true,
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

func fileUsage() string {
	return `usage: racg file <read|patch> [args]

Read plain text or arbitrary files through RACG approval:
  racg file read <path>
  racg file read <path> --max-bytes 65536

Patch plain text files through RACG approval with a unified diff:
  racg file patch <path> --diff-file /tmp/change.patch
  racg file patch <path> --diff '@@ -1 +1 @@...'

Underlying operations:
  read   -> fs.read
  patch  -> fs.patch_unified

Common flags:
  --host URL
  --token TOKEN
  --no-wait
  --poll-interval 500ms
  --wait-timeout 30s
`
}
