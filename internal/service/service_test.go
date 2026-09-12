package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

func TestAuthorityServiceExclusiveOwnershipAndBrokerConnection(t *testing.T) {
	root, err := os.MkdirTemp("", "racg-service-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	config := Config{
		Authority: DefaultAuthorityConfig(),
		Broker:    DefaultBrokerConfig(),
	}
	config.Authority.ServerID = "server"
	config.Authority.StateDir = filepath.Join(root, "authority")
	config.Authority.SocketPath = filepath.Join(root, "authority.sock")
	config.Authority.BrokerUID = os.Getuid()
	config.Authority.BrokerGID = os.Getgid()
	config.Broker.StateDir = filepath.Join(root, "broker")
	config.Broker.SocketPath = config.Authority.SocketPath
	config.Broker.AuthorityUID = os.Getuid()
	config.Broker.AuthorityGID = os.Getgid()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service, err := OpenAuthority(ctx, config.Authority, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAuthority(ctx, config.Authority, signingKey); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("second authority error=%v", err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.Run(ctx) }()

	client, closeBroker, err := ConnectBroker(ctx, config.Broker)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := approval.NewSubmission("server", "un enrolled", []byte(`{"type":"cmd.run"}`), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignSubmission(submission, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubmitAgent(ctx, signed); err == nil || !strings.Contains(err.Error(), "agent is not enrolled") {
		t.Fatalf("authority response=%v", err)
	}
	closeBroker()
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authority service did not stop")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(config.Authority.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("socket cleanup=%v", err)
	}
	reopened, err := OpenAuthority(context.Background(), config.Authority, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
