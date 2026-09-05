package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

func TestLookupRecoversExpiredSubmissionWithoutRepeatingIt(t *testing.T) {
	a, _, server, _, _ := authorityFixture(t)
	ctx := context.Background()
	s, key := agentSubmission(t, a)
	request, err := a.Submit(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(1200, 0) }
	if _, err := a.Submit(ctx, s); err == nil {
		t.Fatal("expired delivery accepted")
	}
	q, err := approval.NewLookup("server", "agent", s.Submission.Nonce, time.Unix(1300, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignLookup(q, key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.LookupSubmission(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	pub := server.Public().(ed25519.PublicKey)
	if err := approval.VerifyLookupResult(q, result, pub, a.now()); err != nil {
		t.Fatal(err)
	}
	if !result.Result.Found || result.Result.Request.Request.RequestID != request.Request.RequestID || result.Result.Status != "PENDING_APPROVAL" {
		t.Fatalf("result=%+v", result)
	}
	// A fresh challenge rejects even a correctly signed old response.
	fresh, err := approval.NewLookup("server", "agent", s.Submission.Nonce, time.Unix(1300, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyLookupResult(fresh, result, pub, a.now()); err == nil {
		t.Fatal("stale result accepted")
	}
	result.Result.Status = "SUCCEEDED"
	if err := approval.VerifyLookupResult(q, result, pub, a.now()); err == nil {
		t.Fatal("forged status accepted")
	}
	var count int
	if err := a.db.QueryRow("SELECT count(*) FROM authority_submissions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("lookup resubmitted operation")
	}
}

func TestLookupDoesNotRevealAnotherAgentsSubmission(t *testing.T) {
	a, _, server, _, _ := authorityFixture(t)
	ctx := context.Background()
	s, _ := agentSubmission(t, a)
	if _, err := a.Submit(ctx, s); err != nil {
		t.Fatal(err)
	}
	pub, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(ctx, "other", pub); err != nil {
		t.Fatal(err)
	}
	q, err := approval.NewLookup("server", "other", s.Submission.Nonce, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignLookup(q, other)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.LookupSubmission(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyLookupResult(q, result, server.Public().(ed25519.PublicKey), a.now()); err != nil {
		t.Fatal(err)
	}
	if result.Result.Found || result.Result.Request != nil {
		t.Fatal("foreign request leaked")
	}
	signed.Lookup.ClientID = "agent"
	if _, err := a.LookupSubmission(ctx, signed); err == nil {
		t.Fatal("impersonated lookup accepted")
	}
}

func TestLookupRejectsRevokedAndExpiredCredentials(t *testing.T) {
	a, _, server, _, _ := authorityFixture(t)
	ctx := context.Background()
	s, key := agentSubmission(t, a)
	q, err := approval.NewLookup("server", "agent", s.Submission.Nonce, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignLookup(q, key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.LookupSubmission(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if result.Result.Found {
		t.Fatal("unknown submission found")
	}
	if err := approval.VerifyLookupResult(q, result, server.Public().(ed25519.PublicKey), time.Unix(1100, 0)); err == nil {
		t.Fatal("expired response accepted")
	}
	a.now = func() time.Time { return time.Unix(1100, 0) }
	if _, err := a.LookupSubmission(ctx, signed); err == nil {
		t.Fatal("expired query accepted")
	}
	a.now = func() time.Time { return time.Unix(1000, 0) }
	if err := a.RevokeAgentTrusted(ctx, "agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LookupSubmission(ctx, signed); err == nil {
		t.Fatal("revoked agent inspected requests")
	}
}
