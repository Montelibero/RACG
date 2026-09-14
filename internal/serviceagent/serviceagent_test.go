package serviceagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
	_ "modernc.org/sqlite"
)

func TestAgentKeyFileRoundTrip(t *testing.T) {
	oldWorkFactor := keyWorkFactor
	keyWorkFactor = 10
	t.Cleanup(func() { keyWorkFactor = oldWorkFactor })
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
	auth, transport, deviceKey, stop := transportFixture(t)
	defer stop()
	ctx := context.Background()
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("downloaded result\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	submission, err := transport.Submit(ctx, []byte(`{"type":"fs.download","payload":{"path":"`+source+`"}}`), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := approval.SignDecision(submission.Request.Request, "device", "ALLOW_ONCE", nil, time.Now().Add(time.Minute), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Consume(ctx, submission.Request.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ExecuteStored(ctx, submission.Request.Request.RequestID, authority.OperationExecutionOptions{}); err != nil {
		t.Fatal(err)
	}
	result, err := transport.Wait(ctx, submission.Nonce, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "SUCCEEDED" || result.Download == nil || string(result.Download.Data) != "downloaded result\n" {
		t.Fatalf("result=%+v", result)
	}
}

func transportFixture(t *testing.T) (*authority.Authority, Transport, ed25519.PrivateKey, func()) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- broker.ServeAuthority(context.Background(), auth, conn, conn)
	}()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := broker.NewAuthorityClient(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	transport := Transport{
		Connection: Connection{Client: client},
		Profile:    Profile{ServerID: "server", PublicKey: serverPublic},
		Key:        &Key{ClientID: "agent", Private: agentKey, Public: agentPublic},
	}
	return auth, transport, deviceKey, func() {
		clientConn.Close()
		listener.Close()
		db.Close()
		if err := <-serverDone; err != nil {
			t.Errorf("authority server: %v", err)
		}
	}
}

func TestTransportStageUploadAuthorizesTarget(t *testing.T) {
	auth, transport, deviceKey, stop := transportFixture(t)
	defer stop()
	ctx := context.Background()
	data := []byte("uploaded by service agent\n")
	staged, err := transport.StageUpload(ctx, data, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.txt")
	operation, err := json.Marshal(map[string]any{
		"type": "fs.upload",
		"payload": map[string]any{
			"path":      target,
			"upload_id": staged.UploadID,
			"mode":      "0600",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	submission, err := transport.Submit(ctx, operation, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(submission.Request.Request.Operation), staged.UploadID) {
		t.Fatalf("operation=%s", submission.Request.Request.Operation)
	}
	decision, err := approval.SignDecision(submission.Request.Request, "device", "ALLOW_ONCE", nil, time.Now().Add(time.Minute), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Consume(ctx, submission.Request.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.ExecuteStored(ctx, submission.Request.Request.RequestID, authority.OperationExecutionOptions{}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != string(data) {
		t.Fatalf("target=%q err=%v", content, err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stat=%v err=%v", info, err)
	}
	if _, err := transport.Wait(ctx, submission.Nonce, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}
