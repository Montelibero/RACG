package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/server"
	"github.com/itolstov/racg/internal/tui"
	"github.com/itolstov/racg/internal/version"
)

type ServeCmd struct {
	stdout io.Writer
	stderr io.Writer
	runUI  func(context.Context, tui.ServeUIConfig) error
}

func NewServeCmd(stdout, stderr io.Writer) *ServeCmd {
	return &ServeCmd{stdout: stdout, stderr: stderr, runUI: tui.RunServeUI}
}

func (c *ServeCmd) Run(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.run(ctx, args)
}

// run keeps the interactive composition testable without a terminal or process-wide signals.
func (c *ServeCmd) run(parent context.Context, args []string) int {
	cfg := config.Defaults()

	headless := false
	socketPath := "/run/racg/pipeline.sock"
	approverID := ""
	publicURL := ""
	approverSetupOut := ""

	fs := flag.NewFlagSet("racg serve", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintln(c.stderr, "usage: racg serve [flags]")
		fmt.Fprintln(c.stderr, "Interactive: start the standalone server and local TUI; no installed service is required.")
		fmt.Fprintln(c.stderr, "Headless: --headless runs the privileged pipeline listening only on --socket, with no public")
		fmt.Fprintln(c.stderr, "port and no TUI; pair it with 'racg remote-approver --socket ...' as the single public entry.")
		fmt.Fprintln(c.stderr, "Manual approval and denial are local to the server TUI in interactive mode.")
		fmt.Fprintln(c.stderr, "Agent tokens cannot approve or deny requests over HTTP (403 REMOTE_DECISION_DISABLED).")
		fmt.Fprintln(c.stderr, "Existing authorized rules may still auto-approve matching requests.")
		fmt.Fprintln(c.stderr, "Manual decisions are applied only after their audit transaction is saved; a storage error leaves the request pending.")
		fmt.Fprintln(c.stderr, "DECISION_PERSISTENCE_FAILED on automatic approval leaves an existing request pending: review its ID in TUI, do not resubmit.")
		fs.PrintDefaults()
	}

	configPath := fs.String("config", "", "path to config.toml")
	profile := fs.String("profile", "", "server profile name; uses a separate persisted DB/rules file")
	fs.StringVar(&cfg.ListenAddr, "listen-addr", cfg.ListenAddr, "interactive listen address")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "interactive listen port")
	fs.Int64Var(&cfg.MaxTransferBytes, "max-transfer-bytes", 0, "deprecated; transfers are approval-gated and unlimited")
	fs.BoolVar(&headless, "headless", false, "run the privileged pipeline headless: listen only on --socket, no public port, no TUI")
	fs.StringVar(&socketPath, "socket", socketPath, "unix socket path for --headless; only the remote-approver facade connects here")
	fs.StringVar(&cfg.ServerID, "server-id", cfg.ServerID, "server identity bound into approver signatures and setup QR; changing it requires approver re-pairing")
	fs.StringVar(&approverID, "approver-id", "", "device identity proposed in the approver setup QR (default: approver-<hostname>)")
	fs.StringVar(&publicURL, "public-url", "", "public base URL of the remote-approver facade, embedded in the setup QR")
	fs.StringVar(&approverSetupOut, "approver-setup-out", "", "write a one-time approver setup QR PNG to this path (requires --public-url)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if headless {
		if socketPath == "" {
			fmt.Fprintln(c.stderr, "--headless requires --socket")
			return 2
		}
		cfg.SocketPath = socketPath
	}
	if approverSetupOut != "" && publicURL == "" {
		fmt.Fprintln(c.stderr, "--approver-setup-out requires --public-url")
		return 2
	}
	if approverID == "" {
		approverID = defaultApproverID()
	}

	if *configPath != "" {
		f, err := os.Open(*configPath)
		if err != nil {
			fmt.Fprintf(c.stderr, "failed to open config: %v\n", err)
			return 2
		}
		defer f.Close()

		if err := config.ApplyTOMLSimple(&cfg, f); err != nil {
			fmt.Fprintf(c.stderr, "failed to parse config: %v\n", err)
			return 2
		}
	}
	if *profile != "" {
		cfg.DBPath = config.ProfileDBPath(*profile)
	}

	s, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(c.stderr, "server init failed: %v\n", err)
		return 1
	}

	ctx, stop := context.WithCancel(parent)
	defer stop()

	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		err := s.Run(ctx, ready)
		errCh <- err
		if err != nil {
			stop()
		}
	}()

	select {
	case <-ready:
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(c.stderr, "server error: %v\n", err)
			return 1
		}
		return 0
	}

	if headless {
		fmt.Fprintf(c.stdout, "pipeline_ready=true\nsocket=%s\ndb_path=%s\npairing_code=%s\napprover_pairing_token=%s\n",
			s.Addr(), cfg.DBPath, s.PairingCode(), s.API().ApproverPairingToken())
	} else {
		fmt.Fprintf(c.stdout, "listening=http://%s\n", s.Addr())
		if *profile != "" {
			fmt.Fprintf(c.stdout, "profile=%s\n", *profile)
		}
		fmt.Fprintf(c.stdout, "db_path=%s\npairing_code=%s\napprover_pairing_token=%s\n",
			cfg.DBPath, s.PairingCode(), s.API().ApproverPairingToken())
	}

	if approverSetupOut != "" {
		if err := writeApproverSetupQR(approverSetupOut, cfg.ServerID, approverID, publicURL, s.API().ApproverPairingToken()); err != nil {
			fmt.Fprintf(c.stderr, "approver setup QR failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(c.stdout, "approver_setup_qr=%s\napprover_id=%s\nendpoint=%s\n",
			approverSetupOut, approverID, publicURL)
	}

	if headless {
		if err := <-errCh; err != nil {
			fmt.Fprintf(c.stderr, "server error: %v\n", err)
			return 1
		}
		return 0
	}

	hostname, _ := os.Hostname()

	// Built-in TUI (tview): pairing page + dashboard + jobs.
	_ = c.runUI(ctx, tui.ServeUIConfig{
		Version:  version.Version,
		Listen:   s.Addr(),
		DBPath:   cfg.DBPath,
		Profile:  *profile,
		Hostname: hostname,
		API:      s.API(),
		Store:    s.Store(),
		ExitFunc: stop,
	})

	stop()
	if err := <-errCh; err != nil {
		fmt.Fprintf(c.stderr, "server error: %v\n", err)
		return 1
	}
	return 0
}

func defaultApproverID() string {
	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		hostname = "racg"
	}
	if i := strings.IndexByte(hostname, '.'); i > 0 {
		hostname = hostname[:i]
	}
	return "approver-" + strings.ToLower(hostname)
}

// writeApproverSetupQR writes a one-time approver enrollment QR. The payload
// matches the Android SetupQrParser v4 schema: the enrollment token must be
// standard base64 of exactly 32 raw bytes.
func writeApproverSetupQR(path, serverID, approverID, publicURL, token string) error {
	payload := map[string]any{
		"v":                4,
		"kind":             "racg.approver.setup",
		"server_id":        serverID,
		"approver_id":      approverID,
		"endpoint":         publicURL,
		"enrollment_token": token,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	code, err := qrcode.New(string(encoded), qrcode.Highest)
	if err != nil {
		return err
	}
	png, err := code.PNG(768)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, png, 0o600)
}
