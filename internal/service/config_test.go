package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultServiceConfigurationIsSeparated(t *testing.T) {
	config := Config{Authority: DefaultAuthorityConfig(), Broker: DefaultBrokerConfig()}
	config.Authority.ServerID = "server"
	config.Authority.BrokerUID = 1
	config.Authority.BrokerGID = 2
	config.Broker.AuthorityUID = 3
	config.Broker.AuthorityGID = 4
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if config.Authority.DatabasePath() != filepath.Join(DefaultAuthorityStateDir, "authority.db") {
		t.Fatalf("database path=%s", config.Authority.DatabasePath())
	}
}

func TestParseServiceConfigurationTOML(t *testing.T) {
	config := Config{Authority: DefaultAuthorityConfig(), Broker: DefaultBrokerConfig()}
	input := strings.NewReader(`
# service configuration
authority_server_id = "prod"
authority_state_dir = "/var/lib/racg-authority"
authority_socket = "/run/racg/authority.sock"
authority_broker_uid = 1001
authority_broker_gid = 2001
broker_state_dir = "/var/lib/racg-broker"
broker_authority_socket = "/run/racg/authority.sock"
broker_authority_uid = 0
broker_authority_gid = 0
unknown_future_key = true
`)
	if err := ApplyTOML(&config, input); err != nil {
		t.Fatal(err)
	}
	if config.Authority.ServerID != "prod" || config.Authority.BrokerUID != 1001 || config.Broker.AuthorityGID != 0 {
		t.Fatalf("config=%+v", config)
	}
	config.Authority.ServerID = "prod"
	config.Authority.BrokerUID = 1001
	config.Authority.BrokerGID = 2001
	config.Broker.AuthorityUID = 0
	config.Broker.AuthorityGID = 0
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceConfigurationRejectsSharedState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "shared")
	config := Config{
		Authority: AuthorityConfig{ServerID: "server", StateDir: state, SocketPath: "/run/racg/authority.sock", BrokerUID: 1, BrokerGID: 2},
		Broker:    BrokerConfig{StateDir: state, SocketPath: "/run/racg/authority.sock", AuthorityUID: 3, AuthorityGID: 4},
	}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "separate") {
		t.Fatalf("validate=%v", err)
	}
}

func TestServiceConfigurationRejectsNestedStateAndSocket(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	tests := []Config{
		{
			Authority: AuthorityConfig{ServerID: "server", StateDir: root, SocketPath: "/run/racg/authority.sock", BrokerUID: 1, BrokerGID: 2},
			Broker:    BrokerConfig{StateDir: filepath.Join(root, "broker"), SocketPath: "/run/racg/authority.sock", AuthorityUID: 3, AuthorityGID: 4},
		},
		{
			Authority: AuthorityConfig{ServerID: "server", StateDir: root, SocketPath: filepath.Join(root, "authority.sock"), BrokerUID: 1, BrokerGID: 2},
			Broker:    BrokerConfig{StateDir: filepath.Join(root, "broker"), SocketPath: filepath.Join(root, "authority.sock"), AuthorityUID: 3, AuthorityGID: 4},
		},
	}
	for index, config := range tests {
		if err := config.Validate(); err == nil {
			t.Logf("overlap=%v", pathsOverlap(config.Authority.StateDir, config.Broker.StateDir))
			t.Fatalf("case %d accepted overlapping state", index)
		}
	}
}

func TestPrepareStateRejectsUnsafeDirectory(t *testing.T) {
	root := t.TempDir()
	symlink := filepath.Join(root, "link")
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirectory(symlink); err == nil {
		t.Fatal("symlinked state accepted")
	}
	openParent := filepath.Join(root, "open")
	if err := os.Mkdir(openParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDirectory(filepath.Join(openParent, "state")); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("writable parent error=%v", err)
	}
}
