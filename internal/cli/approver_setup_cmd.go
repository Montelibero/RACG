package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/itolstov/racg/internal/version"
)

// pipelineAdminClient talks to the privileged pipeline over its unix socket.
// Admin endpoints are served only on that socket (adminAuthorized), so this
// is the SSH-local trust channel from item 4A.
func pipelineAdminClient(ctx context.Context, socketPath string) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

func pipelineAdminPost(ctx context.Context, client *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://pipeline"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var envelope struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&envelope)
		if envelope.Message != "" {
			return fmt.Errorf("%s: %s", envelope.Error, envelope.Message)
		}
		return fmt.Errorf("admin request failed with status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// pipelineServerID reads the server identity through the privileged socket
// so the setup QR binds to the right server.
func pipelineServerID(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://pipeline/v1/info", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var info struct {
		ServerID string `json:"server_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	if strings.TrimSpace(info.ServerID) == "" {
		return "", fmt.Errorf("pipeline did not report server_id; update the racg server binary")
	}
	return info.ServerID, nil
}

type ApproverSetupCmd struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func NewApproverSetupCmd(stdout, stderr io.Writer) *ApproverSetupCmd {
	return &ApproverSetupCmd{stdin: os.Stdin, stdout: stdout, stderr: stderr}
}

// defaultFacadePort mirrors the remote-approver facade default listen port.
func defaultFacadePort() int { return 8777 }

// Run mints a fresh single-use enrollment token over the pipeline socket and
// renders the setup QR directly into the terminal (item 7): headless servers
// have no xdg-open. PNG stays optional via --out.
func (c *ApproverSetupCmd) Run(args []string) int {
	ctx := context.Background()

	socketPath := "/run/racg/pipeline.sock"
	approverID := ""
	publicURL := ""
	outPath := ""

	fs := flag.NewFlagSet("racg approver-setup", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintln(c.stderr, "usage: racg approver-setup --public-url http://server:8777 [flags]")
		fmt.Fprintln(c.stderr, "Mints a fresh single-use approver enrollment token (10 minute TTL, one pairing max)")
		fmt.Fprintln(c.stderr, "and prints the setup QR into this terminal. Run it on the server over SSH;")
		fmt.Fprintln(c.stderr, "every run produces a unique QR that pairs exactly one phone.")
		fs.PrintDefaults()
	}
	fs.StringVar(&socketPath, "socket", socketPath, "pipeline unix socket path")
	fs.StringVar(&publicURL, "public-url", "", "public base URL of the remote-approver facade; omit to pick interactively from detected addresses (tailscale first)")
	fs.StringVar(&approverID, "approver-id", "", "device identity for this phone (default: approver-<hostname>)")
	fs.StringVar(&outPath, "out", "", "additionally write the QR as a PNG file to this path")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if publicURL == "" {
		chosen, err := chooseEndpoint(c.stdin, c.stdout, defaultFacadePort())
		if err != nil {
			fmt.Fprintf(c.stderr, "--public-url is required: %v\n", err)
			return 2
		}
		publicURL = chosen
	}
	if approverID == "" {
		approverID = defaultApproverID()
	}

	client := pipelineAdminClient(ctx, socketPath)
	var enrollment struct {
		ApproverTokenB64 string `json:"approver_token_b64"`
		ExpiresAt        string `json:"expires_at"`
	}
	if err := pipelineAdminPost(ctx, client, "/v1/admin/approver/enrollment", &enrollment); err != nil {
		fmt.Fprintf(c.stderr, "enrollment failed: %v\n", err)
		return 1
	}
	serverID, err := pipelineServerID(ctx, client)
	if err != nil {
		fmt.Fprintf(c.stderr, "server identity lookup failed: %v\n", err)
		return 1
	}

	payload, err := json.Marshal(map[string]any{
		"v":                4,
		"kind":             "racg.approver.setup",
		"server_id":        serverID,
		"approver_id":      approverID,
		"endpoint":         publicURL,
		"enrollment_token": enrollment.ApproverTokenB64,
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "setup payload failed: %v\n", err)
		return 1
	}

	code, err := qrcode.New(string(payload), qrcode.Highest)
	if err != nil {
		fmt.Fprintf(c.stderr, "qr render failed: %v\n", err)
		return 1
	}

	if outPath != "" {
		png, err := code.PNG(768)
		if err == nil {
			if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err == nil {
				if err := os.WriteFile(outPath, png, 0o600); err != nil {
					outPath = ""
				}
			} else {
				outPath = ""
			}
		} else {
			outPath = ""
		}
	}

	fmt.Fprintf(c.stdout, "server_id=%s\napprover_id=%s\nendpoint=%s\nexpires_at=%s\n",
		serverID, approverID, publicURL, enrollment.ExpiresAt)
	fmt.Fprintln(c.stdout)
	fmt.Fprintln(c.stdout, "Scan this QR with the RACG Approver app. It pairs exactly one phone and expires at the time above.")
	fmt.Fprintln(c.stdout)
	if small := code.ToSmallString(true); small != "" {
		fmt.Fprintln(c.stdout, small)
	} else {
		fmt.Fprintln(c.stdout, code.ToString(false))
	}
	if outPath != "" {
		fmt.Fprintf(c.stdout, "png_saved=%s\n", outPath)
	}
	return 0
}

type PairingCodeCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewPairingCodeCmd(stdout, stderr io.Writer) *PairingCodeCmd {
	return &PairingCodeCmd{stdout: stdout, stderr: stderr}
}

// Run mints a fresh agent pairing code over the pipeline socket (item 4A):
// no journal races, no restart needed.
func (c *PairingCodeCmd) Run(args []string) int {
	ctx := context.Background()

	socketPath := "/run/racg/pipeline.sock"
	fs := flag.NewFlagSet("racg pairing-code", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintln(c.stderr, "usage: racg pairing-code [flags]")
		fmt.Fprintln(c.stderr, "Mints a fresh agent pairing code for 'racg login --pairing-code'.")
		fs.PrintDefaults()
	}
	fs.StringVar(&socketPath, "socket", socketPath, "pipeline unix socket path")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	client := pipelineAdminClient(ctx, socketPath)
	var result struct {
		PairingCode       string `json:"pairing_code"`
		ExpiresInSeconds  int    `json:"expires_in_seconds"`
	}
	if err := pipelineAdminPost(ctx, client, "/v1/admin/pairing-code", &result); err != nil {
		fmt.Fprintf(c.stderr, "pairing code failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "pairing_code=%s\nexpires_in_seconds=%d\nserver_version=%s\n",
		result.PairingCode, result.ExpiresInSeconds, version.Version)
	return 0
}
