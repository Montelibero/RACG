package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	devicePublic, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := approval.NewDeviceEnrollment("server", "phone", devicePublic, token, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignDeviceEnrollment(enrollment, deviceKey)
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
