package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/itolstov/racg/internal/broker"
	"github.com/itolstov/racg/internal/service"
)

type ServiceAuthorityCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewServiceAuthorityCmd(stdout, stderr io.Writer) *ServiceAuthorityCmd {
	return &ServiceAuthorityCmd{stdout: stdout, stderr: stderr}
}

func (c *ServiceAuthorityCmd) Run(args []string) int {
	if helpRequested(args) {
		fmt.Fprint(c.stdout, serviceAuthorityUsage())
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.run(ctx, args)
}

func (c *ServiceAuthorityCmd) run(ctx context.Context, args []string) int {
	config := service.DefaultAuthorityConfig()
	execution := service.DefaultExecutionConfig()
	fs := flag.NewFlagSet("racg service-authority", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	configPath := fs.String("config", "", "path to service TOML")
	serverID := fs.String("server-id", config.ServerID, "stable authority/server identity")
	stateDir := fs.String("state-dir", config.StateDir, "authority-owned private state directory")
	socket := fs.String("socket", config.SocketPath, "authority protocol socket for the broker group")
	adminSocket := fs.String("admin-socket", config.AdminSocket, "trusted admin socket (mode 0600)")
	brokerUID := fs.Int("broker-uid", config.BrokerUID, "UID of the unprivileged broker process")
	brokerGID := fs.Int("broker-gid", config.BrokerGID, "GID allowed to connect to the authority socket")
	adminUID := fs.Int("admin-uid", config.AdminUID, "UID allowed to use the admin socket")
	adminGID := fs.Int("admin-gid", config.AdminGID, "GID allowed to use the admin socket")
	defaultTimeout := fs.Int("execution-default-timeout-sec", execution.DefaultTimeoutSec, "default execution timeout")
	maxOutput := fs.Int("execution-max-output-bytes", execution.MaxOutputBytes, "maximum retained output bytes")
	maxTransfer := fs.Int64("execution-max-transfer-bytes", execution.MaxTransferBytes, "maximum transfer bytes")
	killGrace := fs.Int("execution-kill-grace-sec", execution.KillGraceSec, "process-group kill grace")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	changed := changedFlags(fs)
	cfg := service.Config{Authority: config, Broker: service.DefaultBrokerConfig()}
	if err := loadServiceConfig(*configPath, &cfg); err != nil {
		fmt.Fprintf(c.stderr, "service config failed: %v\n", err)
		return 2
	}
	applyStringOverride(changed, "server-id", &cfg.Authority.ServerID, *serverID)
	applyStringOverride(changed, "state-dir", &cfg.Authority.StateDir, *stateDir)
	applyStringOverride(changed, "socket", &cfg.Authority.SocketPath, *socket)
	applyStringOverride(changed, "admin-socket", &cfg.Authority.AdminSocket, *adminSocket)
	applyIntOverride(changed, "broker-uid", &cfg.Authority.BrokerUID, *brokerUID)
	applyIntOverride(changed, "broker-gid", &cfg.Authority.BrokerGID, *brokerGID)
	applyIntOverride(changed, "admin-uid", &cfg.Authority.AdminUID, *adminUID)
	applyIntOverride(changed, "admin-gid", &cfg.Authority.AdminGID, *adminGID)
	applyIntOverride(changed, "execution-default-timeout-sec", &cfg.Authority.Execution.DefaultTimeoutSec, *defaultTimeout)
	applyIntOverride(changed, "execution-max-output-bytes", &cfg.Authority.Execution.MaxOutputBytes, *maxOutput)
	applyIntOverride(changed, "execution-kill-grace-sec", &cfg.Authority.Execution.KillGraceSec, *killGrace)
	applyInt64Override(changed, "execution-max-transfer-bytes", &cfg.Authority.Execution.MaxTransferBytes, *maxTransfer)
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(c.stderr, "service config failed: %v\n", err)
		return 2
	}
	authorityService, err := service.OpenAuthority(ctx, cfg.Authority, nil)
	if err != nil {
		fmt.Fprintf(c.stderr, "authority service failed: %v\n", err)
		return 1
	}
	defer authorityService.Close()
	fmt.Fprintf(c.stdout, "authority_ready=true\nserver_id=%s\nsocket=%s\nadmin_socket=%s\nstate_dir=%s\n",
		cfg.Authority.ServerID, cfg.Authority.SocketPath, cfg.Authority.AdminSocket, cfg.Authority.StateDir)
	if err := authorityService.Run(ctx); err != nil {
		fmt.Fprintf(c.stderr, "authority service failed: %v\n", err)
		return 1
	}
	return 0
}

type ServiceBrokerCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewServiceBrokerCmd(stdout, stderr io.Writer) *ServiceBrokerCmd {
	return &ServiceBrokerCmd{stdout: stdout, stderr: stderr}
}

func (c *ServiceBrokerCmd) Run(args []string) int {
	if helpRequested(args) {
		fmt.Fprint(c.stdout, serviceBrokerUsage())
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.run(ctx, args)
}

func serviceAuthorityUsage() string {
	return `usage: racg service-authority [flags]

Starts the privileged service authority/executor. It owns authority state and
the signing key, verifies all agent/device signatures, consumes decisions once,
and executes stored operations. A crash during execution is reported UNCERTAIN
and is never rerun automatically.

Run it under a dedicated privileged service identity. The broker UID/GID values
identify the exact unprivileged relay process; admin UID/GID identify the exact
trusted administration peer. The admin socket is created with mode 0600.

options:
  --config PATH                     load service TOML before flag overrides
  --server-id ID                    stable authority/server identity
  --state-dir PATH                  authority-owned private state directory
  --socket PATH                     broker protocol socket
  --admin-socket PATH               trusted admin socket
  --broker-uid UID                  exact unprivileged broker UID
  --broker-gid GID                  socket-allowed broker GID
  --admin-uid UID                   exact trusted admin UID
  --admin-gid GID                   socket-allowed admin GID
  --execution-*-...                 timeout/output/transfer/kill-grace settings
  --help                            show this help

Never expose the authority socket directly to an untrusted network.
`
}

func serviceBrokerUsage() string {
	return `usage: racg service-broker [flags]

Starts an unprivileged signed-protocol relay. It forwards protocol bytes between
desktop clients and the local authority but cannot authorize, sign or execute.
The relay verifies the expected authority process UID/GID on every local dial.
Network authentication/isolation is provided by the deployment (for example
Tailscale); use a private listener unless that layer is configured.

options:
  --config PATH             load service TOML before flag overrides
  --state-dir PATH          broker-owned private state directory
  --listen URI              tcp://host:port or unix:///path listener
  --listen-gid GID          Unix listener GID (-1 inherits broker group)
  --authority-socket PATH   local authority protocol socket
  --authority-uid UID       expected authority process UID
  --authority-gid GID       expected authority process GID
  --help                    show this help
`
}

func (c *ServiceBrokerCmd) run(ctx context.Context, args []string) int {
	config := service.DefaultBrokerConfig()
	fs := flag.NewFlagSet("racg service-broker", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	configPath := fs.String("config", "", "path to service TOML")
	stateDir := fs.String("state-dir", config.StateDir, "broker-owned private state directory")
	listen := fs.String("listen", config.ListenURI, "listener URI (tcp://host:port or unix:///path)")
	listenGID := fs.Int("listen-gid", config.ListenGID, "GID for a Unix listener socket (-1 inherits the broker group)")
	authoritySocket := fs.String("authority-socket", config.SocketPath, "local authority protocol socket")
	authorityUID := fs.Int("authority-uid", config.AuthorityUID, "expected authority process UID")
	authorityGID := fs.Int("authority-gid", config.AuthorityGID, "expected authority process GID")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	changed := changedFlags(fs)
	cfg := service.Config{Authority: service.DefaultAuthorityConfig(), Broker: config}
	if err := loadServiceConfig(*configPath, &cfg); err != nil {
		fmt.Fprintf(c.stderr, "service config failed: %v\n", err)
		return 2
	}
	applyStringOverride(changed, "state-dir", &cfg.Broker.StateDir, *stateDir)
	applyStringOverride(changed, "listen", &cfg.Broker.ListenURI, *listen)
	applyStringOverride(changed, "authority-socket", &cfg.Broker.SocketPath, *authoritySocket)
	applyIntOverride(changed, "listen-gid", &cfg.Broker.ListenGID, *listenGID)
	applyIntOverride(changed, "authority-uid", &cfg.Broker.AuthorityUID, *authorityUID)
	applyIntOverride(changed, "authority-gid", &cfg.Broker.AuthorityGID, *authorityGID)
	cfg.Broker = cfg.Broker.Normalized()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(c.stderr, "service config failed: %v\n", err)
		return 2
	}
	relay := &broker.Relay{
		URI:            cfg.Broker.ListenURI,
		AuthorityPath:  cfg.Broker.SocketPath,
		AuthorityPeer:  broker.PeerCredentials{UID: cfg.Broker.AuthorityUID, GID: cfg.Broker.AuthorityGID},
		ListenGroupGID: cfg.Broker.ListenGID,
	}
	if err := relay.Listen(); err != nil {
		fmt.Fprintf(c.stderr, "broker service failed: %v\n", err)
		return 1
	}
	defer relay.Close()
	fmt.Fprintf(c.stdout, "broker_ready=true\nlistener=%s\nauthority_socket=%s\n", relay.Addr(), cfg.Broker.SocketPath)
	if err := relay.Serve(ctx); err != nil {
		fmt.Fprintf(c.stderr, "broker service failed: %v\n", err)
		return 1
	}
	return 0
}

func loadServiceConfig(path string, config *service.Config) error {
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return service.ApplyTOML(config, file)
}

func changedFlags(fs *flag.FlagSet) map[string]bool {
	changed := make(map[string]bool)
	fs.Visit(func(flag *flag.Flag) { changed[flag.Name] = true })
	return changed
}

func applyStringOverride(changed map[string]bool, name string, target *string, value string) {
	if changed[name] {
		*target = value
	}
}

func applyIntOverride(changed map[string]bool, name string, target *int, value int) {
	if changed[name] {
		*target = value
	}
}

func applyInt64Override(changed map[string]bool, name string, target *int64, value int64) {
	if changed[name] {
		*target = value
	}
}
