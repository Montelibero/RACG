package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/broker"
	"github.com/itolstov/racg/internal/serviceagent"
)

type ServiceAgentCmd struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func NewServiceAgentCmdWithInput(stdin io.Reader, stdout, stderr io.Writer) *ServiceAgentCmd {
	return &ServiceAgentCmd{stdin: stdin, stdout: stdout, stderr: stderr}
}

func NewServiceAgentCmd(stdout, stderr io.Writer) *ServiceAgentCmd {
	return NewServiceAgentCmdWithInput(os.Stdin, stdout, stderr)
}

func (c *ServiceAgentCmd) Run(args []string) int {
	if len(args) == 0 || helpRequested(args) {
		fmt.Fprint(c.stdout, serviceAgentUsage())
		return 0
	}
	switch args[0] {
	case "keygen":
		return c.runKeygen(args[1:])
	case "public-key":
		return c.runPublicKey(args[1:])
	case "run":
		return c.runRun(args[1:])
	case "download":
		return c.runDownload(args[1:])
	case "upload":
		return c.runUpload(args[1:])
	case "cancel":
		return c.runCancel(args[1:])
	default:
		fmt.Fprintf(c.stderr, "unknown service-agent command %q\n", args[0])
		return 2
	}
}

func (c *ServiceAgentCmd) runKeygen(args []string) int {
	fs := flag.NewFlagSet("racg service-agent keygen", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	keyPath := fs.String("key", "", "output passphrase-encrypted agent key")
	clientID := fs.String("client-id", "", "agent identity to enroll")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	passphrase, err := c.readPassphrase()
	if err != nil {
		fmt.Fprintf(c.stderr, "keygen failed: %v\n", err)
		return 1
	}
	key, err := serviceagent.GenerateKey(*clientID)
	if err == nil {
		err = serviceagent.SaveKey(*keyPath, key, passphrase)
	}
	if err != nil {
		fmt.Fprintf(c.stderr, "keygen failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "agent_key=true\nclient_id=%s\npublic_key=%s\n", key.ClientID, key.PublicKeyBase64())
	return 0
}

func (c *ServiceAgentCmd) runPublicKey(args []string) int {
	fs := flag.NewFlagSet("racg service-agent public-key", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	keyPath := fs.String("key", "", "passphrase-encrypted agent key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	passphrase, err := c.readPassphrase()
	if err != nil {
		fmt.Fprintf(c.stderr, "public-key failed: %v\n", err)
		return 1
	}
	key, err := serviceagent.LoadKey(*keyPath, passphrase)
	if err != nil {
		fmt.Fprintf(c.stderr, "public-key failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "client_id=%s\npublic_key=%s\n", key.ClientID, key.PublicKeyBase64())
	return 0
}

func (c *ServiceAgentCmd) runRun(args []string) int {
	return c.runProtocol(args, false)
}

func (c *ServiceAgentCmd) runDownload(args []string) int {
	return c.runProtocol(args, true)
}

func (c *ServiceAgentCmd) runUpload(args []string) int {
	fs := flag.NewFlagSet("racg service-agent upload", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	profilePath := fs.String("profile", "", "trusted server profile from service-admin export-profile")
	keyPath := fs.String("key", "", "passphrase-encrypted agent key")
	connect := fs.String("connect", "", "broker/service endpoint URI")
	clientID := fs.String("client-id", "", "agent identity (overrides encrypted key identity)")
	local := fs.String("local", "", "local file to upload")
	remote := fs.String("remote", "", "remote target path")
	mode := fs.String("mode", "", "remote file mode (for example 0644)")
	stageValidity := fs.Duration("stage-validity", time.Hour, "how long immutable staging may be referenced")
	submissionValidity := fs.Duration("submission-validity", time.Hour, "how long the signed submission may be delivered")
	resultValidity := fs.Duration("decision-validity", time.Hour, "recommended decision validity for the approver")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for a terminal result")
	out := fs.String("out", "", "write authenticated result JSON to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *local == "" || *remote == "" {
		fmt.Fprintln(c.stderr, "upload requires --local and --remote")
		return 2
	}
	data, err := os.ReadFile(*local)
	if err != nil {
		fmt.Fprintf(c.stderr, "upload failed: %v\n", err)
		return 1
	}
	transport, closeConn, err := c.newTransport(*profilePath, *keyPath, *connect, *clientID)
	if err != nil {
		fmt.Fprintf(c.stderr, "upload failed: %v\n", err)
		return 1
	}
	defer closeConn()
	staged, err := transport.StageUpload(context.Background(), data, time.Now().Add(*stageValidity))
	if err != nil {
		fmt.Fprintf(c.stderr, "upload failed: %v\n", err)
		return 1
	}
	operation, err := json.Marshal(map[string]any{
		"type": "fs.upload",
		"payload": map[string]any{
			"path":      canonicalRemotePath(*remote),
			"upload_id": staged.UploadID,
			"mode":      *mode,
		},
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "upload failed: %v\n", err)
		return 1
	}
	submission, err := transport.Submit(context.Background(), operation, time.Now().Add(*submissionValidity))
	if err != nil {
		fmt.Fprintf(c.stderr, "upload failed: %v\n", err)
		return 1
	}
	result, err := transport.Wait(context.Background(), submission.Nonce, time.Now().Add(*timeout))
	if err != nil {
		fmt.Fprintf(c.stderr, "upload failed: %v\n", err)
		return 1
	}
	if *out != "" {
		if err := writeAgentResult(*out, submission, result); err != nil {
			fmt.Fprintf(c.stderr, "upload failed: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(c.stdout, "request_id=%s\nstatus=%s\nremote=%s\n", result.Request.Request.RequestID, result.Status, *remote)
	fmt.Fprintf(c.stdout, "decision_validity=%s\n", *resultValidity)
	if result.Execution != nil {
		fmt.Fprintf(c.stdout, "stdout=%q\nstderr=%q\n", result.Execution.Stdout, result.Execution.Stderr)
	}
	if result.Status == "SUCCEEDED" {
		return 0
	}
	return 1
}

func (c *ServiceAgentCmd) runCancel(args []string) int {
	fs := flag.NewFlagSet("racg service-agent cancel", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	profilePath := fs.String("profile", "", "trusted server profile from service-admin export-profile")
	keyPath := fs.String("key", "", "passphrase-encrypted agent key")
	connect := fs.String("connect", "", "broker/service endpoint URI")
	clientID := fs.String("client-id", "", "agent identity (overrides encrypted key identity)")
	requestID := fs.String("request-id", "", "request ID returned by run")
	nonce := fs.String("nonce", "", "submission nonce returned by run (hex)")
	validity := fs.Duration("validity", time.Minute, "how long the signed cancellation may be delivered")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *requestID == "" || *nonce == "" {
		fmt.Fprintln(c.stderr, "cancel requires --request-id and --nonce")
		return 2
	}
	nonceBytes, err := hex.DecodeString(strings.TrimSpace(*nonce))
	if err != nil || len(nonceBytes) != 32 {
		fmt.Fprintln(c.stderr, "nonce must be 64 hexadecimal characters")
		return 2
	}
	transport, closeConn, err := c.newTransport(*profilePath, *keyPath, *connect, *clientID)
	if err != nil {
		fmt.Fprintf(c.stderr, "cancel failed: %v\n", err)
		return 1
	}
	defer closeConn()
	result, err := transport.Cancel(context.Background(), *requestID, nonceBytes, time.Now().Add(*validity))
	if err != nil {
		fmt.Fprintf(c.stderr, "cancel failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "request_id=%s\nauthority_status=%s\ncanceled=%t\n", result.RequestID, result.Status, result.Canceled)
	if result.Canceled {
		return 0
	}
	return 1
}

func (c *ServiceAgentCmd) runProtocol(args []string, download bool) int {
	name := "racg service-agent run"
	if download {
		name = "racg service-agent download"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	profilePath := fs.String("profile", "", "trusted server profile from service-admin export-profile")
	keyPath := fs.String("key", "", "passphrase-encrypted agent key")
	connect := fs.String("connect", "", "broker/service endpoint URI")
	clientID := fs.String("client-id", "", "agent identity (overrides encrypted key identity)")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for a terminal result")
	out := fs.String("out", "", "write authenticated result JSON to this file")
	downloadOutput := fs.String("download-output", "", "write fs.download artifact to this path")
	stdinFile := fs.String("stdin-file", "", "optional local file to stage as command stdin")
	stageValidity := fs.Duration("stage-validity", time.Hour, "how long immutable staging may be referenced")
	submissionValidity := fs.Duration("submission-validity", time.Hour, "how long the signed submission may be delivered")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	var operation []byte
	var stagedData []byte
	var err error
	if err != nil {
		fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
		return 2
	}
	if download {
		operation, err = c.downloadPayload(argv)
	} else {
		operation, stagedData, err = c.runPayload(argv, *stdinFile)
	}
	if *profilePath == "" || *keyPath == "" || *connect == "" {
		fmt.Fprintf(c.stderr, "%s requires --profile, --key and --connect\n", name)
		return 2
	}
	profile, err := serviceagent.LoadProfile(*profilePath)
	if err != nil {
		fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
		return 1
	}
	passphrase, err := c.readPassphrase()
	if err != nil {
		fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
		return 1
	}
	key, err := serviceagent.LoadKey(*keyPath, passphrase)
	if err != nil {
		fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
		return 1
	}
	if *clientID != "" {
		key.ClientID = *clientID
	}
	network, address, err := broker.ParseListenerURI(*connect)
	if err != nil {
		fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, closeConn, err := broker.Dial(ctx, network, address)
	if err != nil {
		fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
		return 1
	}
	defer closeConn()
	transport := serviceagent.Transport{
		Connection: serviceagent.Connection{Client: client},
		Profile:    profile,
		Key:        key,
	}
	if stagedData != nil {
		staged, stageErr := transport.StageUpload(context.Background(), stagedData, time.Now().Add(*stageValidity))
		if stageErr != nil {
			fmt.Fprintf(c.stderr, "%s failed: %v\n", name, stageErr)
			return 1
		}
		var envelope struct {
			Type    string         `json:"type"`
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(operation, &envelope); err != nil {
			fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
			return 1
		}
		envelope.Payload["stdin_upload_id"] = staged.UploadID
		operation, err = json.Marshal(envelope)
		if err != nil {
			fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
			return 1
		}
	}
	submission, err := transport.Submit(ctx, operation, time.Now().Add(*submissionValidity))
	if err != nil {
		fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
		return 1
	}
	result, err := transport.Wait(ctx, submission.Nonce, time.Now().Add(*timeout))
	if err != nil {
		fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
		return 1
	}
	if download && result.Status == "SUCCEEDED" {
		if *downloadOutput == "" {
			fmt.Fprintf(c.stderr, "%s requires --download-output\n", name)
			return 2
		}
		if err := writeServiceDownload(*downloadOutput, result.Download); err != nil {
			fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
			return 1
		}
	}
	if *out != "" {
		if err := writeAgentResult(*out, submission, result); err != nil {
			fmt.Fprintf(c.stderr, "%s failed: %v\n", name, err)
			return 1
		}
	}
	fmt.Fprintf(c.stdout, "request_id=%s\nstatus=%s\n", result.Request.Request.RequestID, result.Status)
	if result.Execution != nil {
		fmt.Fprintf(c.stdout, "exit_code=%d\nstdout=%q\nstderr=%q\n",
			result.Execution.ExitCode, result.Execution.Stdout, result.Execution.Stderr)
	}
	if download && result.Download != nil {
		fmt.Fprintf(c.stdout, "download_output=%s\ndownload_sha256=%s\n", *downloadOutput, result.Download.SHA256)
	}
	if result.Status == "SUCCEEDED" {
		return 0
	}
	return 1
}

func (c *ServiceAgentCmd) downloadPayload(argv []string) ([]byte, error) {
	if len(argv) != 1 || argv[0] == "" {
		return nil, errors.New("download requires one remote PATH")
	}
	return json.Marshal(map[string]any{"type": "fs.download", "payload": map[string]any{"path": canonicalRemotePath(argv[0])}})
}

func (c *ServiceAgentCmd) runPayload(argv []string, stdinFile string) ([]byte, []byte, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, nil, errors.New("run requires argv after --")
	}
	var staged []byte
	if stdinFile != "" {
		data, err := readServiceInput(c.stdin, stdinFile)
		if err != nil {
			return nil, nil, err
		}
		staged = data
	}
	operation, err := json.Marshal(map[string]any{
		"type":    "cmd.run",
		"payload": map[string]any{"argv": argv},
	})
	return operation, staged, err
}

func readServiceInput(stdin io.Reader, path string) ([]byte, error) {
	if path != "-" {
		return os.ReadFile(path)
	}
	if stdin == nil {
		return nil, errors.New("stdin required")
	}
	return io.ReadAll(stdin)
}

func (c *ServiceAgentCmd) newTransport(profilePath, keyPath, connect, clientID string) (serviceagent.Transport, func(), error) {
	profile, err := serviceagent.LoadProfile(profilePath)
	if err != nil {
		return serviceagent.Transport{}, nil, err
	}
	passphrase, err := c.readPassphrase()
	if err != nil {
		return serviceagent.Transport{}, nil, err
	}
	key, err := serviceagent.LoadKey(keyPath, passphrase)
	if err != nil {
		return serviceagent.Transport{}, nil, err
	}
	if clientID != "" {
		key.ClientID = clientID
	}
	network, address, err := broker.ParseListenerURI(connect)
	if err != nil {
		return serviceagent.Transport{}, nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	client, closeConn, err := broker.Dial(ctx, network, address)
	if err != nil {
		cancel()
		return serviceagent.Transport{}, nil, err
	}
	closeAll := func() {
		closeConn()
		cancel()
	}
	return serviceagent.Transport{
		Connection: serviceagent.Connection{Client: client},
		Profile:    profile,
		Key:        key,
	}, closeAll, nil
}

func (c *ServiceAgentCmd) readPassphrase() (string, error) {
	if value := strings.TrimSpace(os.Getenv("RACG_AGENT_PASSPHRASE")); value != "" {
		return value, nil
	}
	return "", errors.New("passphrase required: set RACG_AGENT_PASSPHRASE")
}

func writeAgentResult(path string, submission serviceagent.Submission, result serviceagent.Result) error {
	data, err := json.MarshalIndent(struct {
		RequestID string                         `json:"request_id"`
		Nonce     string                         `json:"nonce"`
		Status    string                         `json:"status"`
		Result    *serviceagent.ExecutionResult  `json:"result,omitempty"`
		Download  *serviceagent.DownloadArtifact `json:"download,omitempty"`
	}{
		RequestID: result.Request.Request.RequestID,
		Nonce:     hex.EncodeToString(submission.Nonce),
		Status:    result.Status,
		Result:    result.Execution,
		Download:  result.Download,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func writeServiceDownload(path string, artifact *serviceagent.DownloadArtifact) error {
	if artifact == nil {
		return errors.New("download artifact missing")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".racg-service-download-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			temporary.Close()
			os.Remove(temporaryName)
		}
	}()
	mode := os.FileMode(0o600)
	if parsed, err := strconv.ParseUint(artifact.Mode, 8, 32); err == nil {
		mode = os.FileMode(parsed) | 0o600
	}
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(artifact.Data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func serviceAgentUsage() string {
	return `usage: racg service-agent <command> [flags]

Authenticated service-mode agent operations. The broker is untrusted: the
server profile pins the authority key, and all requests/results/artifacts are
verified before local use.

commands:
  keygen --key PATH --client-id ID
      create a passphrase-encrypted Ed25519 agent key
  public-key --key PATH
      print the key for trusted admin enrollment
  run [flags] -- argv...
      submit cmd.run, wait for an authenticated result
  download [flags] -- PATH
      request fs.download, wait, verify and atomically save the artifact
  cancel [flags] --request-id ID --nonce HEX
      durably cancel a request before authority dispatch
  upload --local PATH --remote PATH [--mode MODE]
      stage bytes, request fs.upload, wait and verify the result

run/download flags:
  --profile PATH            trusted server profile
  --key PATH                passphrase-encrypted agent key
  --connect URI             broker relay endpoint (tcp:// or unix://)
  --client-id ID            override the ID stored in the key
  --timeout DURATION        terminal-result wait deadline (default 2m)
  --stage-validity DURATION immutable staging reference validity (default 1h)
  --submission-validity DURATION signed submission delivery validity (default 1h)
  --out PATH                write authenticated result JSON
  --download-output PATH    write verified download bytes

cancel flags:
  --profile PATH            trusted server profile
  --key PATH                passphrase-encrypted agent key
  --connect URI             broker relay endpoint (tcp:// or unix://)
  --client-id ID            override the ID stored in the key
  --request-id ID           request ID from run
  --nonce HEX               submission nonce from run --out
  --validity DURATION       signed cancellation delivery validity (default 1m)

Set RACG_AGENT_PASSPHRASE for non-interactive key use. A FAILED/KILLED/TIMED_OUT
status exits nonzero; UNCERTAIN means external effects are unknown and must
never be retried automatically.
`
}
