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

	"fyne.io/fyne/v2/test"
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
}

func TestPendingNotificationSummary(t *testing.T) {
	requests := []approval.SignedRequest{{Request: approval.Request{ClientID: "agent\x1b"}}}
	title, message := pendingNotification(requests)
	if title != "RACG approvals pending" || message == "" || strings.Contains(message, "\x1b") {
		t.Fatalf("title=%q message=%q", title, message)
	}
}

func TestParseTransportAddress(t *testing.T) {
	network, address, err := parseTransportAddress("unix:///run/racg/approver.sock")
	if err != nil || network != "unix" || address != "/run/racg/approver.sock" {
		t.Fatalf("unix=%s %s %v", network, address, err)
	}
	network, address, err = parseTransportAddress("tcp://127.0.0.1:9443")
	if err != nil || network != "tcp" || address != "127.0.0.1:9443" {
		t.Fatalf("tcp=%s %s %v", network, address, err)
	}
	for _, value := range []string{"", "/tmp/socket", "http://example.test", "unix:///tmp/x?x=1", "tcp://host"} {
		if _, _, err := parseTransportAddress(value); err == nil {
			t.Fatalf("endpoint %q accepted", value)
		}
	}
}

type fakeConnection struct {
	pending   approval.SignedRequestListResult
	decision  broker.DecisionSubmission
	serverKey ed25519.PrivateKey
	request   approval.Request
}

func (f *fakeConnection) ListPending(context.Context, approval.SignedRequestList) (approval.SignedRequestListResult, error) {
	return f.pending, nil
}

func (f *fakeConnection) SubmitDecision(_ context.Context, submission broker.DecisionSubmission) (approval.SignedDecisionReceipt, error) {
	f.decision = submission
	return approval.SignDecisionReceipt(f.request, submission.Decision, submission.Challenge, f.serverKey)
}

func TestUIServicePendingAndDecision(t *testing.T) {
	devicePublic, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := approval.SignedRequest{Request: approval.Request{Version: approval.Version, ServerID: "server", RequestID: "request-1", ClientID: "agent", Challenge: make([]byte, 32), Operation: []byte(`{}`)}}
	app := test.NewApp()
	u := newPreviewUI(options{}, app)
	u.canvas()
	u.profileValue = ServerProfile{ServerID: "server", PublicKey: serverPublic}
	u.key = &DeviceKey{ID: "device", Private: devicePrivate, Public: devicePublic}
	connection := &fakeConnection{}
	connection.serverKey = serverKey
	connection.request = request.Request
	u.connection = connection
	u.transportActive = true
	u.applyPending([]approval.SignedRequest{request}, nil)
	u.decisionValidity.SetText("5m")
	if u.requestList.Length() != 1 {
		t.Fatalf("list rows=%d", u.requestList.Length())
	}
	u.selectedIndex = 0
	u.selectedRequest = request
	u.updateServiceButtons()
	if u.serviceAllow.Disabled() {
		t.Fatal("verified pending request did not enable service decision")
	}
	u.sendServiceDecision("ALLOW_ONCE")
	if connection.decision.RequestID == "" {
		t.Fatalf("no submission; status=%q active=%v selected=%+v", u.status.Text, u.transportActive, u.selectedRequest)
	}
	if connection.decision.RequestID != request.Request.RequestID || connection.decision.Decision.Decision.Action != "ALLOW_ONCE" {
		t.Fatalf("submitted=%+v", connection.decision)
	}
	if len(u.serviceRequests) != 0 {
		t.Fatalf("accepted request remained listed status=%q", u.status.Text)
	}
}
