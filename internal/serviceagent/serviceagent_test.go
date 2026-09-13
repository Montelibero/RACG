package serviceagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
	_ "modernc.org/sqlite"
)

func TestAgentKeyFileRoundTrip(t *testing.T) {
	keyWorkFactor = 10
	defer func() { keyWorkFactor = 18 }()
	key, err := GenerateKey("agent")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.key")
	if err := SaveKey(path, key, "correct horse"); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKey(path, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ClientID != key.ClientID || !ed25519.PublicKey.Equal(loaded.Public, key.Public) {
		t.Fatal("loaded key changed")
	}
	if _, err := LoadKey(path, "wrong horse"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
}

func TestTransportSubmitsWaitsAndDeliversDownload(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
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
	auth, err := authority.New(context.Background(), db, "server", serverKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.EnrollAgentTrusted(context.Background(), "agent", agentPublic); err != nil {
		t.Fatal(err)
	}
	if err := auth.EnrollTrusted(context.Background(), "device", devicePublic); err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- broker.ServeAuthority(context.Background(), auth, serverConn, serverConn) }()
	client, err := broker.NewAuthorityClient(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	transport := Transport{
		Connection: Connection{Client: client},
		Profile:    Profile{ServerID: "server", PublicKey: serverPublic},
		Key:        &Key{ClientID: "agent", Private: agentKey, Public: agentPublic},
	}
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("downloaded result\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	submission, err := transport.Submit(context.Background(), []byte(`{"type":"fs.download","payload":{"path":"`+source+`"}}`), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := approval.SignDecision(submission.Request.Request, "device", "ALLOW_ONCE", nil, time.Now().Add(time.Minute), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Consume(context.Background(), submission.Request.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ExecuteStored(context.Background(), submission.Request.Request.RequestID, authority.OperationExecutionOptions{}); err != nil {
		t.Fatal(err)
	}
	result, err := transport.Wait(context.Background(), submission.Nonce, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "SUCCEEDED" || result.Download == nil || string(result.Download.Data) != "downloaded result\n" {
		t.Fatalf("result=%+v", result)
	}
	closeClient := func() { clientConn.Close() }
	closeClient()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
