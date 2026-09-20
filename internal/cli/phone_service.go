package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/itolstov/racg/internal/approvalbridge"
	qrcode "github.com/skip2/go-qrcode"
)

type PhoneServiceCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewPhoneServiceCmd(stdout, stderr io.Writer) *PhoneServiceCmd {
	return &PhoneServiceCmd{stdout: stdout, stderr: stderr}
}

func (c *PhoneServiceCmd) Run(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.run(ctx, args)
}

func (c *PhoneServiceCmd) run(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("racg phone-service", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	listen := fs.String("listen", "127.0.0.1:9443", "private phone API listen address")
	bridge := fs.String("bridge", "/run/racg/approval.sock", "local approval bridge socket")
	devices := fs.String("devices", "", "phone device registry path")
	pairingCode := fs.String("pairing-code", os.Getenv("RACG_PHONE_PAIRING_CODE"), "one-time phone pairing code")
	serverID := fs.String("server-id", "", "server name shown by the phone")
	publicURL := fs.String("public-url", "", "phone-reachable base URL for this service")
	setupOut := fs.String("setup-out", "", "write a one-time setup QR PNG to this path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *devices == "" {
		fmt.Fprintln(c.stderr, "devices registry path is required")
		return 2
	}
	if *publicURL == "" || *setupOut == "" {
		fmt.Fprintln(c.stderr, "public URL and setup QR output are required")
		return 2
	}

	if *pairingCode == "" {
		b := make([]byte, 18)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintf(c.stderr, "phone service failed: %v\n", err)
			return 1
		}
		*pairingCode = strings.ToLower(base64.RawURLEncoding.EncodeToString(b))
	}
	if *serverID == "" {
		hostname, _ := os.Hostname()
		*serverID = "server-" + hostname
	}
	if *pairingCode == "" {
		token := make([]byte, 24)
		if _, err := rand.Read(token); err != nil {
			fmt.Fprintf(c.stderr, "phone service failed: %v\n", err)
			return 1
		}
		*pairingCode = base64.RawURLEncoding.EncodeToString(token)
	}
	if *setupOut != "" {
		payload := map[string]any{
			"v":                4,
			"kind":             "racg.approver.setup",
			"server_id":        *serverID,
			"endpoint":         *publicURL,
			"enrollment_token": *pairingCode,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			fmt.Fprintf(c.stderr, "phone service failed: %v\n", err)
			return 1
		}
		code, err := qrcode.New(string(encoded), qrcode.Highest)
		if err != nil {
			fmt.Fprintf(c.stderr, "phone service failed: %v\n", err)
			return 1
		}
		png, err := code.PNG(768)
		if err != nil {
			fmt.Fprintf(c.stderr, "phone service failed: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*setupOut, png, 0o600); err != nil {
			fmt.Fprintf(c.stderr, "phone service failed: %v\n", err)
			return 1
		}
	}
	phoneServer := approvalbridge.NewPhoneServer(*pairingCode)
	bridgeClient := approvalbridge.NewClient(*bridge)

	handler := &phoneHandler{bridge: bridgeClient, phone: phoneServer}
	fmt.Fprintf(c.stdout, "phone_service_ready=true\nlisten=%s\nbridge=%s\ndevices=%s\npairing_code=%s\n",
		*listen, *bridge, *devices, *pairingCode)

	if err := handler.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(c.stderr, "phone service error: %v\n", err)
		return 1
	}
	return 0
}
