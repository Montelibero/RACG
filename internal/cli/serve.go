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
	stdout io.Writer
	stderr io.Writer
}

func NewServeCmd(stdout, stderr io.Writer) *ServeCmd {
	return &ServeCmd{stdout: stdout, stderr: stderr}
}

func (c *ServeCmd) Run(args []string) int {
	cfg := config.Defaults()

	fs := flag.NewFlagSet("racg serve", flag.ContinueOnError)
	fs.SetOutput(c.stderr)

	configPath := fs.String("config", "", "path to config.toml")
	profile := fs.String("profile", "", "server profile name; uses a separate persisted DB/rules file")
	fs.StringVar(&cfg.ListenAddr, "listen-addr", cfg.ListenAddr, "listen address")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "listen port")

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Run(ctx, ready)
	}()

	<-ready
	fmt.Fprintf(c.stdout, "listening=http://%s\n", s.Addr())
	if *profile != "" {
		fmt.Fprintf(c.stdout, "profile=%s\n", *profile)
	}
	fmt.Fprintf(c.stdout, "db_path=%s\n", cfg.DBPath)
	fmt.Fprintf(c.stdout, "pairing_code=%s\n", s.PairingCode())

	// Built-in TUI (tview): pairing page + dashboard + jobs.
	_ = tui.RunServeUI(ctx, tui.ServeUIConfig{
		Version:  version.Version,
		Listen:   s.Addr(),
		DBPath:   cfg.DBPath,
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
