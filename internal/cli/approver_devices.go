package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/store"
)

// ApproverDevicesCmd administers enrolled remote approver devices in the
// privileged SQLite registry: list, re-enable and revoke.
type ApproverDevicesCmd struct {
	stdout io.Writer
	stderr io.Writer
	dbPath string
}

func NewApproverDevicesCmd(stdout, stderr io.Writer, defaultDBPath string) *ApproverDevicesCmd {
	return &ApproverDevicesCmd{stdout: stdout, stderr: stderr, dbPath: defaultDBPath}
}

func (c *ApproverDevicesCmd) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg approver-devices <list|revoke|enable> [args]")
		return 2
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("racg approver-devices list", flag.ContinueOnError)
		fs.SetOutput(c.stderr)
		db := fs.String("db", c.dbPath, "sqlite db path")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		return c.runList(*db)
	case "revoke":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintln(c.stderr, "usage: racg approver-devices revoke <device_id> [--db PATH]")
			return 2
		}
		deviceID := strings.TrimSpace(args[1])
		fs := flag.NewFlagSet("racg approver-devices revoke", flag.ContinueOnError)
		fs.SetOutput(c.stderr)
		db := fs.String("db", c.dbPath, "sqlite db path")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		return c.runSetEnabled(*db, deviceID, false)
	case "enable":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintln(c.stderr, "usage: racg approver-devices enable <device_id> [--db PATH]")
			return 2
		}
		deviceID := strings.TrimSpace(args[1])
		fs := flag.NewFlagSet("racg approver-devices enable", flag.ContinueOnError)
		fs.SetOutput(c.stderr)
		db := fs.String("db", c.dbPath, "sqlite db path")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		return c.runSetEnabled(*db, deviceID, true)
	default:
		fmt.Fprintln(c.stderr, "usage: racg approver-devices <list|revoke|enable> [args]")
		return 2
	}
}

func (c *ApproverDevicesCmd) openStore(dbPath string) (*store.Store, context.CancelFunc, int) {
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(c.stderr, "approver-devices: open store: %v\n", err)
		return nil, nil, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := st.Migrate(ctx); err != nil {
		cancel()
		_ = st.Close()
		fmt.Fprintf(c.stderr, "approver-devices: migrate store: %v\n", err)
		return nil, nil, 1
	}
	return st, func() { cancel(); _ = st.Close() }, 0
}

func (c *ApproverDevicesCmd) runList(dbPath string) int {
	st, closeFn, code := c.openStore(dbPath)
	if st == nil {
		return code
	}
	defer closeFn()

	devices, err := st.ListApproverDevices(context.Background(), 1000)
	if err != nil {
		fmt.Fprintf(c.stderr, "approver-devices: list: %v\n", err)
		return 1
	}
	if len(devices) == 0 {
		fmt.Fprintln(c.stdout, "no approver devices enrolled")
		return 0
	}
	for _, d := range devices {
		status := "enabled"
		if !d.Enabled {
			status = "REVOKED"
		}
		fmt.Fprintf(c.stdout, "%s\t%s\tcreated=%s\n", d.DeviceID, status, d.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	return 0
}

func (c *ApproverDevicesCmd) runSetEnabled(dbPath, deviceID string, enabled bool) int {
	st, closeFn, code := c.openStore(dbPath)
	if st == nil {
		return code
	}
	defer closeFn()

	if err := st.SetApproverDeviceEnabled(context.Background(), deviceID, enabled, time.Now().UTC()); err != nil {
		fmt.Fprintf(c.stderr, "approver-devices: %v\n", err)
		return 1
	}
	if enabled {
		fmt.Fprintf(c.stdout, "enabled %s\n", deviceID)
	} else {
		fmt.Fprintf(c.stdout, "revoked %s\n", deviceID)
	}
	return 0
}
