package authority

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

func TestListPendingReturnsSignedSnapshotWithoutMutation(t *testing.T) {
	a, _, server, deviceKey, first := authorityFixture(t)
	ctx := context.Background()
	second, err := a.FreezeTrusted(ctx, "agent", "session", []byte(`{"type":"fs.read","payload":{"path":"/tmp/second"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RevokeTrusted(ctx, "desktop"); err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollTrusted(ctx, "desktop", deviceKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	list, err := approval.NewRequestList("server", "desktop", time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedList, err := approval.SignRequestList(list, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.ListPending(ctx, signedList)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyRequestListResult(list, result, server.Public().(ed25519.PublicKey), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if len(result.Result.Requests) != 2 {
		t.Fatalf("requests=%d", len(result.Result.Requests))
	}
	if _, err := a.Consume(ctx, first.Request.RequestID, signedDecision(t, first.Request, deviceKey, "ALLOW_ONCE")); err != nil {
		t.Fatal(err)
	}
	result, err = a.ListPending(ctx, signedList)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Result.Requests) != 1 || result.Result.Requests[0].Request.RequestID != second.Request.RequestID {
		t.Fatalf("requests=%+v", result.Result.Requests)
	}
}

func TestListPendingRejectsRevokedAndForgedDevices(t *testing.T) {
	a, _, _, deviceKey, _ := authorityFixture(t)
	ctx := context.Background()
	list, err := approval.NewRequestList("server", "desktop", time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignRequestList(list, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RevokeTrusted(ctx, "desktop"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListPending(ctx, signed); err == nil {
		t.Fatal("revoked device listed pending requests")
	}
	signed.List.DeviceID = "stranger"
	if _, err := a.ListPending(ctx, signed); err == nil {
		t.Fatal("forged device identity accepted")
	}
}
