package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
	"github.com/itolstov/racg/internal/service"
	qrcode "github.com/skip2/go-qrcode"
)

type ServiceAdminCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewServiceAdminCmd(stdout, stderr io.Writer) *ServiceAdminCmd {
	return &ServiceAdminCmd{stdout: stdout, stderr: stderr}
}

func (c *ServiceAdminCmd) Run(args []string) int {
	if len(args) == 0 || helpRequested(args) {
		fmt.Fprint(c.stdout, serviceAdminUsage())
		return 0
	}
	fs := flag.NewFlagSet("racg service-admin", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	socket := fs.String("socket", "/run/racg/authority-admin.sock", "trusted authority admin socket")
	adminUID := fs.Int("admin-uid", os.Getuid(), "exact allowed admin UID")
	adminGID := fs.Int("admin-gid", os.Getgid(), "exact allowed admin GID")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	subcommand := fs.Arg(0)
	peer := broker.PeerCredentials{UID: *adminUID, GID: *adminGID}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, closeConn, err := service.ConnectAdminSocket(ctx, *socket, peer)
	if err != nil {
		fmt.Fprintf(c.stderr, "admin connect failed: %v\n", err)
		return 1
	}
	defer closeConn()

	switch subcommand {
	case "identity":
		return c.runIdentity(ctx, client, fs.Args()[1:])
	case "export-profile":
		return c.runExportProfile(ctx, client, fs.Args()[1:])
	case "list":
		return c.runList(ctx, client, fs.Args()[1:])
	case "enroll", "rotate":
		return c.runEnroll(ctx, client, fs.Args()[1:], subcommand == "rotate")
	case "revoke":
		return c.runRevoke(ctx, client, fs.Args()[1:])
	case "create-setup":
		return c.runCreateSetup(ctx, client, fs.Args()[1:])
	default:
		fmt.Fprintf(c.stderr, "unknown service-admin command %q\n", subcommand)
		return 2
	}
}

func (c *ServiceAdminCmd) runIdentity(ctx context.Context, client *service.AdminClient, args []string) int {
	fs := flag.NewFlagSet("racg service-admin identity", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	identity, err := client.Identity(ctx)
	if err != nil {
		fmt.Fprintf(c.stderr, "identity failed: %v\n", err)
		return 1
	}
	if *asJSON {
		return c.printJSON(identity)
	}
	fmt.Fprintf(c.stdout, "server_id=%s\npublic_key=%s\nversion=%d\n",
		identity.ServerID, base64.StdEncoding.EncodeToString(identity.PublicKey), identity.Version)
	return 0
}

func (c *ServiceAdminCmd) runExportProfile(ctx context.Context, client *service.AdminClient, args []string) int {
	fs := flag.NewFlagSet("racg service-admin export-profile", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	out := fs.String("out", "", "output profile path")
	force := fs.Bool("force", false, "replace an existing profile")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || !filepath.IsAbs(*out) {
		fmt.Fprintln(c.stderr, "export-profile requires an absolute --out path")
		return 2
	}
	identity, err := client.Identity(ctx)
	if err != nil {
		fmt.Fprintf(c.stderr, "export-profile failed: %v\n", err)
		return 1
	}
	encoded, err := json.Marshal(struct {
		ServerID  string `json:"server_id"`
		PublicKey []byte `json:"public_key"`
	}{identity.ServerID, identity.PublicKey})
	if err != nil {
		fmt.Fprintf(c.stderr, "export-profile failed: %v\n", err)
		return 1
	}
	if _, err := os.Lstat(*out); err == nil && !*force {
		fmt.Fprintf(c.stderr, "export-profile refused: output exists (use --force)\n")
		return 2
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(c.stderr, "export-profile failed: %v\n", err)
		return 1
	}
	if err := writeAdminFileAtomic(*out, encoded, 0o600); err != nil {
		fmt.Fprintf(c.stderr, "export-profile failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "profile_exported=true\nout=%s\nserver_id=%s\n", *out, identity.ServerID)
	return 0
}

func (c *ServiceAdminCmd) runList(ctx context.Context, client *service.AdminClient, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg service-admin list <devices|agents|grants> [--json]")
		return 2
	}
	kind := args[0]
	fs := flag.NewFlagSet("racg service-admin list "+kind, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch kind {
	case "devices", "agents":
		credentials, err := listCredentials(ctx, client, kind)
		if err != nil {
			fmt.Fprintf(c.stderr, "list failed: %v\n", err)
			return 1
		}
		if *asJSON {
			return c.printJSON(credentials)
		}
		for _, credential := range credentials {
			fmt.Fprintf(c.stdout, "%s\trevoked=%t\tpublic_key=%s\n",
				credential.ID, credential.Revoked, base64.StdEncoding.EncodeToString(credential.PublicKey))
		}
		return 0
	case "grants":
		grants, err := client.ListGrants(ctx)
		if err != nil {
			fmt.Fprintf(c.stderr, "list failed: %v\n", err)
			return 1
		}
		if *asJSON {
			return c.printJSON(grants)
		}
		for _, grant := range grants {
			expiry := grant.ExpiresAt
			if expiry == "" {
				expiry = "never"
			}
			fmt.Fprintf(c.stdout, "%s\tclient=%s\tdevice=%s\texpires=%s\trevoked=%t\n",
				grant.ID, grant.ClientID, grant.DeviceID, expiry, grant.Revoked)
		}
		return 0
	default:
		fmt.Fprintf(c.stderr, "unknown list kind %q\n", kind)
		return 2
	}
}

func (c *ServiceAdminCmd) runEnroll(ctx context.Context, client *service.AdminClient, args []string, rotate bool) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg service-admin enroll <device|agent> --id ID --public-key (BASE64|PATH)")
		return 2
	}
	kind := args[0]
	fs := flag.NewFlagSet("racg service-admin "+subcommandName("enroll", rotate)+" "+kind, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	id := fs.String("id", "", "device or agent identity")
	publicKey := fs.String("public-key", "", "base64 Ed25519 public key, or path to a base64 file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	key, err := parseEd25519PublicKey(*publicKey)
	if err != nil {
		fmt.Fprintf(c.stderr, "public key invalid: %v\n", err)
		return 2
	}
	if *id == "" {
		fmt.Fprintln(c.stderr, "id is required")
		return 2
	}
	switch kind {
	case "device":
		err := client.RotateDevice(ctx, *id, key)
		if err != nil {
			fmt.Fprintf(c.stderr, "enroll failed: %v\n", err)
			return 1
		}
	case "agent":
		err := client.RotateAgent(ctx, *id, key)
		if err != nil {
			fmt.Fprintf(c.stderr, "enroll failed: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(c.stderr, "unknown credential kind %q\n", kind)
		return 2
	}
	verb := "enrolled"
	if rotate {
		verb = "rotated"
	}
	fmt.Fprintf(c.stdout, "%s=%s\npublic_key=%s\n", kind, verb, base64.StdEncoding.EncodeToString(key))
	return 0
}

func (c *ServiceAdminCmd) runRevoke(ctx context.Context, client *service.AdminClient, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg service-admin revoke <device|agent|grant> --id ID")
		return 2
	}
	kind := args[0]
	fs := flag.NewFlagSet("racg service-admin revoke "+kind, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	id := fs.String("id", "", "identity to revoke")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *id == "" {
		fmt.Fprintln(c.stderr, "id is required")
		return 2
	}
	switch kind {
	case "device":
		err := client.RevokeDevice(ctx, *id)
		if err != nil {
			fmt.Fprintf(c.stderr, "revoke failed: %v\n", err)
			return 1
		}
	case "agent":
		err := client.RevokeAgent(ctx, *id)
		if err != nil {
			fmt.Fprintf(c.stderr, "revoke failed: %v\n", err)
			return 1
		}
	case "grant":
		err := client.RevokeGrant(ctx, *id)
		if err != nil {
			fmt.Fprintf(c.stderr, "revoke failed: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(c.stderr, "unknown credential kind %q\n", kind)
		return 2
	}
	fmt.Fprintf(c.stdout, "revoked=%s\n", *id)
	return 0
}

// runCreateSetup renders a one-time mobile setup QR without exposing token
// bytes on the terminal. The PNG uses the command's atomic 0600 file writer.
func (c *ServiceAdminCmd) runCreateSetup(ctx context.Context, client *service.AdminClient, args []string) int {
	fs := flag.NewFlagSet("racg service-admin create-setup", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	endpoint := fs.String("endpoint", "", "reachable broker URI (tcp://host:port)")
	deviceID := fs.String("device-id", "", "permanent approver identity (default: generated)")
	out := fs.String("out", "", "output setup-QR PNG path")
	validFor := fs.Duration("valid-for", 10*time.Minute, "setup token lifetime")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *endpoint == "" || *out == "" {
		fmt.Fprintln(c.stderr, "create-setup requires --endpoint and --out")
		return 2
	}
	if *validFor < time.Second {
		fmt.Fprintln(c.stderr, "create-setup requires a validity of at least one second")
		return 2
	}
	if *deviceID == "" {
		*deviceID = "approver-" + uuid.NewString()
	}
	if err := validateBrokerEndpoint(*endpoint); err != nil {
		fmt.Fprintf(c.stderr, "endpoint invalid: %v\n", err)
		return 2
	}
	identity, err := client.Identity(ctx)
	if err != nil {
		fmt.Fprintf(c.stderr, "create-setup failed: %v\n", err)
		return 1
	}
	setup, err := client.CreateDeviceSetup(ctx, *deviceID, *validFor)
	if err != nil {
		fmt.Fprintf(c.stderr, "create-setup failed: %v\n", err)
		return 1
	}
	payload, err := json.Marshal(struct {
		Version         int    `json:"v"`
		Kind            string `json:"kind"`
		ServerID        string `json:"server_id"`
		PublicKey       []byte `json:"server_public_key"`
		ApproverID      string `json:"approver_id"`
		Endpoint        string `json:"endpoint"`
		EnrollmentToken []byte `json:"enrollment_token"`
	}{
		Version:         2,
		Kind:            "racg.approver.setup",
		ServerID:        identity.ServerID,
		PublicKey:       identity.PublicKey,
		ApproverID:      setup.DeviceID,
		Endpoint:        *endpoint,
		EnrollmentToken: setup.Token,
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "create-setup failed: %v\n", err)
		return 1
	}
	code, err := qrcode.New(string(payload), qrcode.Highest)
	if err != nil {
		fmt.Fprintf(c.stderr, "create-setup failed: %v\n", err)
		return 1
	}
	png, err := code.PNG(768)
	if err != nil {
		fmt.Fprintf(c.stderr, "create-setup failed: %v\n", err)
		return 1
	}
	if err := writeAdminFileAtomic(*out, png, 0o600); err != nil {
		fmt.Fprintf(c.stderr, "create-setup failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "setup_created=true\nout=%s\nserver_id=%s\ndevice_id=%s\nexpires_at=%s\n",
		*out, identity.ServerID, setup.DeviceID, setup.ExpiresAt)
	return 0
}

func validateBrokerEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return err
	}
	switch parsed.Scheme {
	case "tcp", "tcp4", "tcp6":
	default:
		return errors.New("mobile setup requires tcp://, tcp4:// or tcp6://")
	}
	if parsed.Host == "" {
		return errors.New("endpoint requires host and port")
	}
	if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
		return fmt.Errorf("endpoint requires host and port: %w", err)
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("tcp endpoint accepts host and port only")
	}
	return nil
}

func listCredentials(ctx context.Context, client *service.AdminClient, kind string) ([]authority.TrustedCredential, error) {
	if kind == "devices" {
		return client.ListDevices(ctx)
	}
	return client.ListAgents(ctx)
}

func subcommandName(base string, rotate bool) string {
	if rotate {
		return "rotate"
	}
	return base
}

func parseEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("public key required")
	}
	if value == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		value = string(data)
	} else if strings.HasPrefix(value, "@") {
		data, err := os.ReadFile(strings.TrimPrefix(value, "@"))
		if err != nil {
			return nil, err
		}
		value = string(data)
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "hex:") {
		return hex.DecodeString(strings.TrimPrefix(value, "hex:"))
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
	}
	return decoded, nil
}

func writeAdminFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
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
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
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

func (c *ServiceAdminCmd) printJSON(value any) int {
	encoder := json.NewEncoder(c.stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(c.stderr, "encode JSON failed: %v\n", err)
		return 1
	}
	return 0
}

func serviceAdminUsage() string {
	return `usage: racg service-admin [flags] <command>

Trusted local administration over the authority admin socket. The process must
run under the exact admin UID/GID configured for the authority. The socket peer
identity is the credential; commands carry no bearer token.

global flags:
  --socket PATH   trusted authority admin socket
  --admin-uid UID exact allowed admin UID (default: current UID)
  --admin-gid GID exact allowed admin GID (default: current GID)

commands:
  identity
      show the pinned authority identity
  export-profile --out PATH [--force]
      write the desktop server profile with mode 0600
  list devices|agents|grants [--json]
      inspect enrolled credentials and reusable grants
  enroll device|agent --id ID --public-key BASE64|@PATH
      enroll a new permanent credential
  rotate device|agent --id ID --public-key BASE64|@PATH
      replace a credential; old pending signatures stop verifying
  revoke device|agent|grant --id ID
      revoke a credential or reusable grant
  create-setup --endpoint tcp://HOST:PORT --out PATH [--device-id ID] [--valid-for 10m]
      create a one-time mobile setup QR as a mode-0600 PNG; the phone generates
      and signs its own approver key. Treat the PNG as secret until scanned and
      keep the endpoint on a protected network such as Tailscale.

Never run this command from an untrusted process, and never accept identity
material from a broker message.
`
}

var _ = hex.EncodeToString
