package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSubmissionOwnsBuffersAndSeparatesSignatureDomains(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := []byte(`{"argv":["echo"]}`)
	s, err := NewSubmission("server", "agent", operation, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	operation[0] = '!'
	signed, err := SignSubmission(s, key)
	if err != nil {
		t.Fatal(err)
	}
	s.Operation[0] = '!'
	s.Nonce[0] ^= 1
	if err := VerifySubmission(signed, "server", "agent", pub, time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := VerifySubmission(signed, "server", "agent", nil, time.Unix(1000, 0)); err == nil {
		t.Fatal("invalid public key accepted")
	}
	if _, err := SignSubmission(signed.Submission, nil); err == nil {
		t.Fatal("invalid private key accepted")
	}
	// The same key cannot reuse a signature from another protocol domain.
	payload, err := message("decision", signed.Submission)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = ed25519.Sign(key, payload)
	if err := VerifySubmission(signed, "server", "agent", pub, time.Unix(1000, 0)); err == nil {
		t.Fatal("cross-domain signature accepted")
	}
}
