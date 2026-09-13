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
	"github.com/itolstov/racg/internal/broker"
)

func adminServiceFixture(t *testing.T) (*AuthorityService, AuthorityConfig, func()) {
	t.Helper()
	root, err := os.MkdirTemp("", "racg-admin-test-")
	if err != nil {
		t.Fatal(err)
	}
	cleanupRoot := func() { os.RemoveAll(root) }
	t.Cleanup(cleanupRoot)
	config := DefaultAuthorityConfig()
	config.ServerID = "server"
	config.StateDir = filepath.Join(root, "state")
	config.SocketPath = filepath.Join(root, "authority.sock")
	config.AdminSocket = filepath.Join(root, "admin.sock")
	config.BrokerUID = os.Getuid()
	config.BrokerGID = os.Getgid()
	config.AdminUID = os.Getuid()
	config.AdminGID = os.Getgid()
	service, err := OpenAuthority(context.Background(), config, nil)
	if err != nil {
		cleanupRoot()
		t.Fatal(err)
	}
	return service, config, nil
}

func brokerConfigForAdmin(config AuthorityConfig) BrokerConfig {
	return BrokerConfig{
		StateDir:     filepath.Join(filepath.Dir(config.StateDir), "broker"),
		SocketPath:   config.SocketPath,
		AuthorityUID: config.AdminUID,
		AuthorityGID: config.AdminGID,
	}
}

func TestAdminSocketEnrollsRotatesAndRevokes(t *testing.T) {
	service, config, _ := adminServiceFixture(t)
	defer service.Close()
	keyPath := config.PrivateKeyPath()
	info, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode=%v", info.Mode())
	}
	original, err := LoadAuthoritySigningKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.Run(ctx) }()
	admin, closeAdmin, err := ConnectAdmin(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	agentPublic, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.RotateAgent(ctx, "agent", agentPublic); err != nil {
		t.Fatal(err)
	}
	if err := admin.RotateDevice(ctx, "device", devicePublic); err != nil {
		t.Fatal(err)
	}
	agents, err := admin.ListAgents(ctx)
	if err != nil || len(agents) != 1 || agents[0].ID != "agent" {
		t.Fatalf("agents=%+v err=%v", agents, err)
	}
	devices, err := admin.ListDevices(ctx)
	if err != nil || len(devices) != 1 || devices[0].Revoked {
		t.Fatalf("devices=%+v err=%v", devices, err)
	}
	brokerClient, closeBroker, err := ConnectBroker(ctx, brokerConfigForAdmin(config))
	if err != nil {
		t.Fatal(err)
	}
	submission, err := approval.NewSubmission("server", "agent", []byte(`{"type":"cmd.run","payload":{"argv":["/bin/echo","admin"]}}`), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedSubmission, err := approval.SignSubmission(submission, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	signedRequest, err := brokerClient.SubmitAgent(ctx, signedSubmission)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := approval.SignDecision(signedRequest.Request, "device", "ALLOW_ONCE", nil, time.Now().Add(time.Minute), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := brokerClient.SubmitDecision(ctx, broker.DecisionSubmission{
		RequestID: signedRequest.Request.RequestID,
		Decision:  decision,
		Challenge: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDecisionReceipt(signedRequest.Request, decision, receipt, make([]byte, 32), devicePublic, original.Public().(ed25519.PublicKey), time.Now()); err != nil {
		t.Fatal(err)
	}
	lookup, err := approval.NewLookup("server", "agent", submission.Nonce, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedLookup, err := approval.SignLookup(lookup, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		lookupResult, err := brokerClient.LookupSubmission(ctx, signedLookup)
		if err != nil {
			t.Fatal(err)
		}
		if err := approval.VerifyLookupResult(lookup, lookupResult, original.Public().(ed25519.PublicKey), time.Now()); err != nil {
			t.Fatal(err)
		}
		if lookupResult.Result.Status == "SUCCEEDED" {
			if lookupResult.Result.Result == nil || lookupResult.Result.Result.Stdout != "admin\n" {
				t.Fatalf("lookup result=%+v output=%q stderr=%q", lookupResult.Result, lookupResult.Result.Result.Stdout, lookupResult.Result.Result.Stderr)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("execution did not finish: %+v", lookupResult.Result)
		}
		time.Sleep(5 * time.Millisecond)
	}
	newDevicePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.RotateDevice(ctx, "device", newDevicePublic); err != nil {
		t.Fatal(err)
	}
	expiredSubmission, err := approval.NewSubmission("server", "agent", []byte(`{"type":"cmd.run","payload":{"argv":["/bin/echo","second"]}}`), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedExpiredSubmission, err := approval.SignSubmission(expiredSubmission, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest, err := brokerClient.SubmitAgent(ctx, signedExpiredSubmission)
	if err != nil {
		t.Fatal(err)
	}
	oldDecision, err := approval.SignDecision(secondRequest.Request, "device", "DENY", nil, time.Now().Add(time.Minute), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := brokerClient.SubmitDecision(ctx, broker.DecisionSubmission{RequestID: secondRequest.Request.RequestID, Decision: oldDecision, Challenge: make([]byte, 32)}); err == nil {
		t.Fatal("rotated-away device key accepted")
	}
	if err := admin.RevokeDevice(ctx, "device"); err != nil {
		t.Fatal(err)
	}
	devices, err = admin.ListDevices(ctx)
	if err != nil || len(devices) != 1 || !devices[0].Revoked {
		t.Fatalf("rotated devices=%+v err=%v", devices, err)
	}
	closeBroker()
	closeAdmin()
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("admin/broker service did not stop")
	}
}

func TestLoadAuthoritySigningKeyRejectsUnsafeFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "authority.key")
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthoritySigningKey(path); err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("invalid pem error=%v", err)
	}
	if err := os.WriteFile(path, []byte("not pem"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthoritySigningKey(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("unsafe mode error=%v", err)
	}
}
