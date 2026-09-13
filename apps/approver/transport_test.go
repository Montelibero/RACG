package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
	_ "modernc.org/sqlite"
)

func transportFixture(t *testing.T) (Transport, *DeviceKey, approval.SignedRequest, func()) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
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
	request, err := auth.FreezeTrusted(context.Background(), "agent", "", []byte(`{"type":"cmd.run","payload":{"argv":["/bin/echo","transport"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- broker.ServeAuthority(context.Background(), auth, serverConn, serverConn) }()
	connection, err := NewProtocolConnection(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	transport := Transport{
		Connection: connection,
		Profile:    ServerProfile{ServerID: "server", PublicKey: serverPublic},
	}
	key := &DeviceKey{ID: "device", Private: devicePrivate, Public: devicePublic}
	cleanup := func() {
		clientConn.Close()
		serverConn.Close()
		if err := <-serverDone; err != nil {
			t.Errorf("authority server: %v", err)
		}
		db.Close()
	}
	return transport, key, request, cleanup
}

func TestTransportPollsPendingAndSubmitsSignedDecision(t *testing.T) {
	transport, key, request, cleanup := transportFixture(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests, err := transport.PendingRequests(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || requests[0].Request.RequestID != request.Request.RequestID {
		t.Fatalf("requests=%+v", requests)
	}
	receipt, err := transport.SubmitDecision(ctx, key, requests[0], "ALLOW_ONCE", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Receipt.Status != "AUTHORIZED" {
		t.Fatalf("receipt=%+v", receipt)
	}
	requests, err = transport.PendingRequests(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 0 {
		t.Fatalf("consumed request remained pending: %+v", requests)
	}
	if _, err := transport.SubmitDecision(ctx, key, request, "DENY", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("decision replay accepted")
	}
}

func TestPendingNotificationSummary(t *testing.T) {
	requests := []approval.SignedRequest{{Request: approval.Request{ClientID: "agent\x1b"}}}
	title, message := pendingNotification(requests)
	if title != "RACG approvals pending" || message == "" || strings.Contains(message, "\x1b") {
		t.Fatalf("title=%q message=%q", title, message)
	}
}
