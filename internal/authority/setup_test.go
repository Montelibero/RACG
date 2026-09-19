package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	_ "modernc.org/sqlite"
)

func TestDeviceSetupTokenIsSingleUse(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	a, err := New(context.Background(), db, "server", serverKey, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	token, expiresAt, err := a.CreateDeviceSetupTrusted(context.Background(), "phone", time.Minute)
	if err != nil || len(token) != 32 || !expiresAt.Equal(time.Unix(1060, 0).UTC()) {
		t.Fatalf("setup token=%x expires=%v err=%v", token, expiresAt, err)
	}
	devicePrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, err := x509.MarshalPKIXPublicKey(&devicePrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pollPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pollPublic, err := x509.MarshalPKIXPublicKey(&pollPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := approval.NewDeviceEnrollmentWithKeyType(
		"server",
		"phone",
		approval.KeyTypeECDSAP256,
		devicePublic,
		pollPublic,
		token,
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignDeviceEnrollment(enrollment, devicePrivate)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := a.EnrollDevice(context.Background(), approval.DeviceEnrollmentSubmission{
		Enrollment: signed,
		Token:      token,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDeviceEnrollmentReceipt(
		signed,
		receipt,
		serverKey.Public().(ed25519.PublicKey),
		now,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := a.EnrollDevice(context.Background(), approval.DeviceEnrollmentSubmission{
		Enrollment: signed,
		Token:      token,
	}); err == nil {
		t.Fatal("setup token reused")
	}

	agentPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(context.Background(), "agent", agentPublic); err != nil {
		t.Fatal(err)
	}
	request, err := a.FreezeTrusted(context.Background(), "agent", "", []byte(`{"type":"fs.read"}`))
	if err != nil {
		t.Fatal(err)
	}
	list, err := approval.NewRequestList("server", "phone", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedList, err := approval.SignRequestListWithKeyType(list, approval.KeyTypeECDSAP256, pollPrivate)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.ListPending(context.Background(), signedList)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyRequestListResult(list, result, serverKey.Public().(ed25519.PublicKey), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(result.Result.Requests) != 1 || result.Result.Requests[0].Request.RequestID != request.Request.RequestID {
		t.Fatalf("pending result=%+v", result.Result)
	}

	pollDecision, err := approval.SignDecisionWithKeyType(
		request.Request,
		"phone",
		"DENY",
		nil,
		now.Add(time.Minute),
		approval.KeyTypeECDSAP256,
		pollPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(context.Background(), request.Request.RequestID, pollDecision); err == nil {
		t.Fatal("poll key authorized a decision")
	}
}

func TestDeviceSetupRefusesExistingDevice(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), db, "server", serverKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollTrusted(context.Background(), "phone", devicePublic); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.CreateDeviceSetupTrusted(context.Background(), "phone", time.Minute); err == nil {
		t.Fatal("setup token accepted for enrolled device")
	}
}
