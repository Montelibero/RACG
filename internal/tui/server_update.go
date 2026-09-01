package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rivo/tview"
)

type serverUpdatePhase string

const (
	updateChecking    serverUpdatePhase = "checking"
	updateCurrent     serverUpdatePhase = "current"
	updateAvailable   serverUpdatePhase = "available"
	updateInstalling  serverUpdatePhase = "installing"
	updateInstalled   serverUpdatePhase = "installed"
	updateUnavailable serverUpdatePhase = "unavailable"
	updateFailed      serverUpdatePhase = "failed"
)

const (
	serverUpdateCheckTimeout   = 3 * time.Second
	serverUpdateInstallTimeout = 2 * time.Minute
)

var serverUpdateCommandContext = exec.CommandContext

type serverUpdateStatus struct {
	Phase   serverUpdatePhase
	Latest  string
	Message string
}

func checkServerUpdate(ctx context.Context) serverUpdateStatus {
	executable, err := os.Executable()
	if err != nil {
		return serverUpdateStatus{Phase: updateUnavailable, Message: err.Error()}
	}
	cmd := serverUpdateCommandContext(ctx, executable, "update", "--check")
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		return serverUpdateStatus{Phase: updateUnavailable, Message: commandError(err, out)}
	}
	status, err := parseUpdateCheckOutput(string(out))
	if err != nil {
		return serverUpdateStatus{Phase: updateUnavailable, Message: err.Error()}
	}
	return status
}

func installServerUpdate(ctx context.Context, latest string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := serverUpdateCommandContext(ctx, executable, "update", "--version", strings.TrimSpace(latest))
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(commandError(err, out))
	}
	return nil
}

func parseUpdateCheckOutput(text string) (serverUpdateStatus, error) {
	values := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	latest := values["latest_version"]
	if latest == "" {
		return serverUpdateStatus{}, errors.New("update check did not return latest_version")
	}
	if strings.EqualFold(values["update_available"], "true") {
		return serverUpdateStatus{Phase: updateAvailable, Latest: latest}, nil
	}
	return serverUpdateStatus{Phase: updateCurrent, Latest: latest}, nil
}

func commandError(err error, output []byte) string {
	message := strings.TrimSpace(string(output))
	message = strings.Join(strings.Fields(message), " ")
	if message == "" {
		return err.Error()
	}
	return fmt.Sprintf("%v: %s", err, message)
}

func serverUpdateText(current string, status serverUpdateStatus) string {
	switch status.Phase {
	case updateChecking:
		return "update check: checking"
	case updateCurrent:
		return "update check: up to date"
	case updateAvailable:
		return fmt.Sprintf("Update available: %s -> %s", current, status.Latest)
	case updateInstalling:
		return fmt.Sprintf("installing RACG %s", status.Latest)
	case updateInstalled:
		return fmt.Sprintf("installed: %s  running: %s  restart required", status.Latest, current)
	case updateFailed:
		return "update failed: " + status.Message
	default:
		return "update check: unavailable"
	}
}

func serverUpdateButton(status serverUpdateStatus) (label string, enabled bool) {
	switch status.Phase {
	case updateAvailable:
		return "Update " + status.Latest, true
	case updateFailed:
		return "Retry update", status.Latest != ""
	case updateInstalling:
		return "Installing...", false
	case updateInstalled:
		return "Restart needed", false
	case updateCurrent:
		return "Up to date", false
	case updateChecking:
		return "Checking...", false
	default:
		return "Unavailable", false
	}
}

func (s *uiState) setServerUpdate(status serverUpdateStatus) {
	s.mu.Lock()
	s.serverUpdate = status
	s.mu.Unlock()
}

func (s *uiState) serverUpdateSnapshot() serverUpdateStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverUpdate
}

func (s *uiState) refreshServerUpdateUI() {
	s.refreshMainTabs()
	if s.pairingRefresh != nil {
		s.pairingRefresh()
	}
}

func (s *uiState) startServerUpdateCheck(ctx context.Context, app *tview.Application) {
	s.setServerUpdate(serverUpdateStatus{Phase: updateChecking})
	go func() {
		checkCtx, cancel := context.WithTimeout(ctx, serverUpdateCheckTimeout)
		defer cancel()
		status := checkServerUpdate(checkCtx)
		if ctx.Err() != nil {
			return
		}
		s.setServerUpdate(status)
		app.QueueUpdateDraw(s.refreshServerUpdateUI)
	}()
}
