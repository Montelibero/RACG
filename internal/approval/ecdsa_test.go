package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func TestECDSAP256DeviceSignatures(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	request, err := NewRequest("server", "request", "agent", "session", []byte(`{"type":"fs.read"}`))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := SignDecisionWithKeyType(
		request,
		"phone",
		"ALLOW_ONCE",
		nil,
		now.Add(time.Minute),
		KeyTypeECDSAP256,
		private,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDecisionWithKeyType(request, decision, "phone", KeyTypeECDSAP256, public, now); err != nil {
		t.Fatal(err)
	}

	list, err := NewRequestList("server", "phone", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedList, err := SignRequestListWithKeyType(list, KeyTypeECDSAP256, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequestListWithKeyType(signedList, "server", "phone", KeyTypeECDSAP256, public, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Logf("valid_until=%s", list.ValidUntil)
}
