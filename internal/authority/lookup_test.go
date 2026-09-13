package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
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

func TestLookupReturnsExecutionResultAndDownloadArtifact(t *testing.T) {
	a, _, server, deviceKey, _ := authorityFixture(t)
	ctx := context.Background()
	directory := t.TempDir()
	source := directory + "/snapshot-source.txt"
	if err := os.WriteFile(source, []byte("downloaded bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	operation := []byte(`{"type":"fs.download","payload":{"path":"` + source + `"}}`)
	submission, err := approval.NewSubmission("server", "agent", operation, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(ctx, "agent", public); err != nil {
		t.Fatal(err)
	}
	signedSubmission, err := approval.SignSubmission(submission, key)
	if err != nil {
		t.Fatal(err)
	}
	request, err := a.Submit(ctx, signedSubmission)
	if err != nil {
		t.Fatal(err)
	}
	decision := signedDecision(t, request.Request, deviceKey, "ALLOW_ONCE")
	if _, err := a.Consume(ctx, request.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ExecuteStored(ctx, request.Request.RequestID, OperationExecutionOptions{}); err != nil {
		t.Fatal(err)
	}
	lookup, err := approval.NewLookup("server", "agent", submission.Nonce, time.Unix(1200, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedLookup, err := approval.SignLookup(lookup, key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.LookupSubmission(ctx, signedLookup)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := server.Public().(ed25519.PublicKey)
	if err := approval.VerifyLookupResult(lookup, result, serverKey, a.now()); err != nil {
		t.Fatal(err)
	}
	if result.Result.Status != "SUCCEEDED" || result.Result.Result == nil || result.Result.Result.Stdout == "" {
		t.Fatalf("lookup=%+v", result.Result)
	}
	if result.Result.Download == nil || string(result.Result.Download.Data) != "downloaded bytes\n" {
		t.Fatalf("download=%+v", result.Result.Download)
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
