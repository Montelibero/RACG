package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestDeviceEnrollmentAndReceiptBinding(t *testing.T) {
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	token := bytes.Repeat([]byte{9}, 32)
	enrollment, err := NewDeviceEnrollment("server", "phone", devicePublic, token, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignDeviceEnrollment(enrollment, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceEnrollment(signed, "server", now); err != nil {
		t.Fatal(err)
	}
	receipt, err := SignDeviceEnrollmentReceipt(signed, now, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceEnrollmentReceipt(signed, receipt, serverPublic, now); err != nil {
		t.Fatal(err)
	}

	wrongDevicePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceEnrollment(signed, "other", now); err == nil {
		t.Fatal("wrong server accepted")
	}
	if err := VerifyDeviceEnrollment(signed, "server", now.Add(time.Minute)); err == nil {
		t.Fatal("expired enrollment accepted")
	}
	changed := signed
	changed.Enrollment.DeviceID = "attacker"
	if VerifyDeviceEnrollment(changed, "server", now) == nil {
		t.Fatal("modified enrollment accepted")
	}
	changed.Enrollment = signed.Enrollment
	changed.Signature[0] ^= 1
	if VerifyDeviceEnrollment(changed, "server", now) == nil {
		t.Fatal("forged enrollment accepted")
	}
	changed.Enrollment = signed.Enrollment
	changed.Enrollment.PublicKey = wrongDevicePublic
	if _, err := SignDeviceEnrollment(changed.Enrollment, deviceKey); err == nil {
		t.Fatal("key substitution accepted")
	}

	badReceipt := receipt
	badReceipt.Receipt.PublicKey = wrongDevicePublic
	if VerifyDeviceEnrollmentReceipt(signed, badReceipt, serverPublic, now) == nil {
		t.Fatal("receipt key substitution accepted")
	}
	badReceipt = receipt
	badReceipt.Signature[0] ^= 1
	if VerifyDeviceEnrollmentReceipt(signed, badReceipt, serverPublic, now) == nil {
		t.Fatal("forged receipt accepted")
	}
}
