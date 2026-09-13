package broker

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
	_ "modernc.org/sqlite"
)

func TestRelayForwardsSignedProtocol(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
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
	if err := auth.EnrollTrusted(context.Background(), "device", devicePublic); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.FreezeTrusted(context.Background(), "agent", "", []byte(`{"type":"cmd.run","payload":{"argv":["/bin/echo","relay"]}}`)); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "authority.sock")
	authorityListener, err := ListenUnix(socket, PeerCredentials{UID: os.Getuid(), GID: os.Getegid()}, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	defer authorityListener.Close()
	authorityDone := make(chan error, 1)
	go func() {
		authorityDone <- ServeAuthorityUnix(context.Background(), authorityListener, PeerCredentials{UID: os.Getuid(), GID: os.Getegid()}, auth)
	}()

	relay := &Relay{
		URI:           "tcp://127.0.0.1:0",
		AuthorityPath: socket,
		AuthorityPeer: PeerCredentials{UID: os.Getuid(), GID: os.Getegid()},
	}
	if err := relay.Listen(); err != nil {
		t.Fatal(err)
	}
	relayDone := make(chan error, 1)
	go func() { relayDone <- relay.Serve(context.Background()) }()

	conn, err := net.Dial("tcp", relay.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client, err := NewAuthorityClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	list, err := approval.NewRequestList("server", "device", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedList, err := approval.SignRequestList(list, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ListPending(context.Background(), signedList)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyRequestListResult(list, result, serverPublic, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(result.Result.Requests) != 1 {
		t.Fatalf("requests=%d", len(result.Result.Requests))
	}
	conn.Close()
	relay.Close()
	authorityListener.Close()
	select {
	case err := <-relayDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}
