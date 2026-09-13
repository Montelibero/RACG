package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"fyne.io/fyne/v2"
	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/broker"
)

// Connection is the protocol subset used by the desktop. It accepts the same
// signed authority protocol as a broker; the desktop never receives a key.
type Connection interface {
	ListPending(context.Context, approval.SignedRequestList) (approval.SignedRequestListResult, error)
	SubmitDecision(context.Context, broker.DecisionSubmission) (approval.SignedDecisionReceipt, error)
}

type ProtocolConnection struct {
	client *broker.AuthorityClient
}

func NewProtocolConnection(conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}) (*ProtocolConnection, error) {
	client, err := broker.NewAuthorityClient(conn)
	if err != nil {
		return nil, err
	}
	return &ProtocolConnection{client: client}, nil
}

func DialProtocol(ctx context.Context, network, address string) (*ProtocolConnection, func(), error) {
	if network == "" || address == "" {
		return nil, nil, errors.New("transport network and address required")
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, nil, err
	}
	connection, err := NewProtocolConnection(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return connection, func() { conn.Close() }, nil
}

func (c *ProtocolConnection) ListPending(ctx context.Context, signed approval.SignedRequestList) (approval.SignedRequestListResult, error) {
	return c.client.ListPending(ctx, signed)
}

func (c *ProtocolConnection) SubmitDecision(ctx context.Context, submission broker.DecisionSubmission) (approval.SignedDecisionReceipt, error) {
	return c.client.SubmitDecision(ctx, submission)
}

// Transport verifies every response against the SSH-enrolled server profile and
// signs decisions with the local unlocked device key.
type Transport struct {
	Connection Connection
	Profile    ServerProfile
	Now        func() time.Time
}

func (t Transport) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t Transport) validate(key *DeviceKey) error {
	if t.Connection == nil {
		return errors.New("server connection required")
	}
	if key == nil || len(key.Private) != ed25519.PrivateKeySize || key.ID == "" {
		return errors.New("signing key is locked")
	}
	return validateProfile(t.Profile)
}

// PendingRequests returns an authority-signed point-in-time snapshot. Pending
// status is not a safety statement.
func (t Transport) PendingRequests(ctx context.Context, key *DeviceKey) ([]approval.SignedRequest, error) {
	if err := t.validate(key); err != nil {
		return nil, err
	}
	list, err := approval.NewRequestList(t.Profile.ServerID, key.ID, t.now().Add(time.Minute))
	if err != nil {
		return nil, err
	}
	signedList, err := approval.SignRequestList(list, key.Private)
	if err != nil {
		return nil, err
	}
	result, err := t.Connection.ListPending(ctx, signedList)
	if err != nil {
		return nil, err
	}
	if err := approval.VerifyRequestListResult(list, result, t.Profile.PublicKey, t.now()); err != nil {
		return nil, err
	}
	return result.Result.Requests, nil
}

// SubmitDecision sends the locally signed envelope and verifies the authority
// receipt against both device and pinned server identity.
func (t Transport) SubmitDecision(ctx context.Context, key *DeviceKey, request approval.SignedRequest, action string, validUntil time.Time) (approval.SignedDecisionReceipt, error) {
	if err := t.validate(key); err != nil {
		return approval.SignedDecisionReceipt{}, err
	}
	switch action {
	case "ALLOW_ONCE", "DENY":
	default:
		return approval.SignedDecisionReceipt{}, fmt.Errorf("transport does not support action %q", action)
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return approval.SignedDecisionReceipt{}, err
	}
	decision, err := approval.SignDecision(request.Request, key.ID, action, nil, validUntil, key.Private)
	if err != nil {
		return approval.SignedDecisionReceipt{}, err
	}
	receipt, err := t.Connection.SubmitDecision(ctx, broker.DecisionSubmission{
		RequestID: request.Request.RequestID,
		Decision:  decision,
		Challenge: challenge,
	})
	if err != nil {
		return approval.SignedDecisionReceipt{}, err
	}
	if err := approval.VerifyDecisionReceipt(request.Request, decision, receipt, challenge, key.Public, t.Profile.PublicKey, t.now()); err != nil {
		return approval.SignedDecisionReceipt{}, err
	}
	return receipt, nil
}

// Poller repeatedly fetches a signed snapshot and delegates rendering and
// de-duplication to the caller. Callbacks run on the poll goroutine.
type Poller struct {
	Connection Connection
	Profile    ServerProfile
	Now        func() time.Time
	Interval   time.Duration
	OnPending  func([]approval.SignedRequest, error)
}

func (p Poller) Run(ctx context.Context, key *DeviceKey) error {
	transport := Transport{Connection: p.Connection, Profile: p.Profile, Now: p.Now}
	interval := p.Interval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	p.OnPending(transport.PendingRequests(ctx, key))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			p.OnPending(transport.PendingRequests(ctx, key))
		}
	}
}

// NotifyPending uses the desktop notification service. Fyne does not expose a
// read-back API; UI tests assert the pure summary text separately.
func NotifyPending(app fyne.App, requests []approval.SignedRequest) error {
	if app == nil || len(requests) == 0 {
		return nil
	}
	title, message := pendingNotification(requests)
	app.SendNotification(&fyne.Notification{Title: title, Content: message})
	return nil
}

func pendingNotification(requests []approval.SignedRequest) (string, string) {
	if len(requests) == 0 {
		return "", ""
	}
	first := visibleText(requests[0].Request.ClientID)
	summary := fmt.Sprintf("%d pending request(s); newest agent: %s", len(requests), first)
	return "RACG approvals pending", summary
}
