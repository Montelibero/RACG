package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/server"
	"github.com/itolstov/racg/internal/tui"
	"github.com/itolstov/racg/internal/version"
)

type ServeCmd struct {
	stdout      io.Writer
	stderr      io.Writer
	runUI       func(context.Context, tui.ServeUIConfig) error
	phone       bool
	phoneBridge string
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

	phone := false
	phoneBridge := "/run/racg/approval.sock"
	fs := flag.NewFlagSet("racg serve", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintln(c.stderr, "usage: racg serve [flags]")
		fmt.Fprintln(c.stderr, "Start the standalone server and local TUI; no installed service is required.")
		fmt.Fprintln(c.stderr, "Manual approval and denial are local to the server TUI.")
		fmt.Fprintln(c.stderr, "Agent tokens cannot approve or deny requests over HTTP (403 REMOTE_DECISION_DISABLED).")
		fmt.Fprintln(c.stderr, "Existing authorized rules may still auto-approve matching requests.")
		fmt.Fprintln(c.stderr, "Manual decisions are applied only after their audit transaction is saved; a storage error leaves the request pending.")
		fmt.Fprintln(c.stderr, "DECISION_PERSISTENCE_FAILED on automatic approval leaves an existing request pending: review its ID in TUI, do not resubmit.")
		fs.PrintDefaults()
	}

	configPath := fs.String("config", "", "path to config.toml")
	profile := fs.String("profile", "", "server profile name; uses a separate persisted DB/rules file")
	fs.StringVar(&cfg.ListenAddr, "listen-addr", cfg.ListenAddr, "listen address")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "listen port")
	fs.Int64Var(&cfg.MaxTransferBytes, "max-transfer-bytes", 0, "deprecated; transfers are approval-gated and unlimited")
	fs.BoolVar(&phone, "phone", false, "run headless compatibility server with phone approval bridge")
	fs.StringVar(&phoneBridge, "phone-bridge", "/run/racg/approval.sock", "local phone approval bridge socket")

	if err := fs.Parse(args); err != nil {
		return 2
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
	fmt.Fprintf(c.stdout, "listening=http://%s\n", s.Addr())
	if *profile != "" {
		fmt.Fprintf(c.stdout, "profile=%s\n", *profile)
	}
	fmt.Fprintf(c.stdout, "db_path=%s\n", cfg.DBPath)
	fmt.Fprintf(c.stdout, "pairing_code=%s\n", s.PairingCode())
	if phone {
		fmt.Fprintf(c.stdout, "phone_mode=true\nphone_bridge=%s\n", phoneBridge)
		if err := c.runPhoneBridge(ctx, s.API()); err != nil {
			fmt.Fprintf(c.stderr, "phone bridge error: %v\n", err)
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
