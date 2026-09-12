package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
	_ "modernc.org/sqlite"
)

func authorityFixture(t *testing.T) (*Authority, *sql.DB, ed25519.PrivateKey, ed25519.PrivateKey, approval.SignedRequest) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	_, server, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, device, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), db, "server", server, func() time.Time { return time.Unix(1000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollTrusted(context.Background(), "desktop", pub); err != nil {
		t.Fatal(err)
	}
	request, err := a.FreezeTrusted(context.Background(), "agent", "session", []byte(`{"type":"cmd.run","payload":{"argv":["/bin/echo","approved"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	return a, db, server, device, request
}

func signedDecision(t *testing.T, r approval.Request, key ed25519.PrivateKey, action string) approval.SignedDecision {
	t.Helper()
	d, err := approval.SignDecision(r, "desktop", action, nil, time.Unix(1100, 0), key)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAuthorityConsumptionAndReplay(t *testing.T) {
	for _, action := range []string{"ALLOW_ONCE", "DENY"} {
		t.Run(action, func(t *testing.T) {
			a, db, server, key, r := authorityFixture(t)
			ctx := context.Background()
			d := signedDecision(t, r.Request, key, action)
			original := string(r.Request.Operation)
			r.Request.Operation[0] = '!'
			got, err := a.Consume(ctx, r.Request.RequestID, d)
			if err != nil {
				t.Fatal(err)
			}
			if string(got.Operation) != original {
				t.Fatal("did not return frozen operation")
			}
			// Reopen the file with a new connection, not an in-memory consumed set.
			var sequence int
			var name, path string
			if err := db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &path); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			freshDB, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer freshDB.Close()
			reopened, err := New(ctx, freshDB, "server", server, func() time.Time { return time.Unix(1001, 0) })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reopened.Consume(ctx, r.Request.RequestID, d); err == nil {
				t.Fatal("replay accepted after reopen")
			}
			_, status, err := reopened.Request(ctx, r.Request.RequestID)
			want := "AUTHORIZED"
			if action == "DENY" {
				want = "DENIED"
			}
			if err != nil || status != want {
				t.Fatalf("status=%s err=%v", status, err)
			}
		})
	}
}

func TestAuthorityRejectsUntrustedDecisions(t *testing.T) {
	for _, attack := range []string{"unknown device", "revoked", "wrong key", "other request", "changed operation", "expired", "changed action", "reusable grant"} {
		t.Run(attack, func(t *testing.T) {
			a, _, _, key, r := authorityFixture(t)
			ctx := context.Background()
			d := signedDecision(t, r.Request, key, "ALLOW_ONCE")
			switch attack {
			case "unknown device":
				d.Decision.DeviceID = "stranger"
			case "revoked":
				if err := a.RevokeTrusted(ctx, "desktop"); err != nil {
					t.Fatal(err)
				}
			case "wrong key":
				_, wrong, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				d = signedDecision(t, r.Request, wrong, "ALLOW_ONCE")
			case "other request":
				other, err := a.FreezeTrusted(ctx, "agent", "session", r.Request.Operation)
				if err != nil {
					t.Fatal(err)
				}
				d = signedDecision(t, other.Request, key, "ALLOW_ONCE")
			case "changed operation":
				r.Request.Operation = []byte(`{"type":"cmd.run","payload":{"argv":["/bin/echo","different"]}}`)
				d = signedDecision(t, r.Request, key, "ALLOW_ONCE")
			case "expired":
				var err error
				d, err = approval.SignDecision(r.Request, "desktop", "ALLOW_ONCE", nil, time.Unix(1000, 0), key)
				if err != nil {
					t.Fatal(err)
				}
			case "changed action":
				d.Decision.Action = "DENY"
			case "reusable grant":
				var err error
				d, err = approval.SignDecision(r.Request, "desktop", "ALLOW_ALWAYS", &approval.Grant{Scope: []byte(`{}`)}, time.Unix(1100, 0), key)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.Consume(ctx, r.Request.RequestID, d); err == nil {
				t.Fatal("untrusted decision accepted")
			}
			_, status, err := a.Request(ctx, r.Request.RequestID)
			if err != nil || status != "PENDING_APPROVAL" {
				t.Fatalf("status=%s err=%v", status, err)
			}
		})
	}
}

func TestAuthorityFailedCommitCanBeRetried(t *testing.T) {
	a, db, _, key, r := authorityFixture(t)
	ctx := context.Background()
	if _, err := db.Exec("CREATE TRIGGER fail_consume BEFORE UPDATE ON authority_requests BEGIN SELECT RAISE(ABORT, 'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	d := signedDecision(t, r.Request, key, "ALLOW_ONCE")
	if _, err := a.Consume(ctx, r.Request.RequestID, d); err == nil {
		t.Fatal("ignored transaction failure")
	}
	_, status, err := a.Request(ctx, r.Request.RequestID)
	if err != nil || status != "PENDING_APPROVAL" {
		t.Fatalf("status=%s err=%v", status, err)
	}
	if _, err := db.Exec("DROP TRIGGER fail_consume"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, r.Request.RequestID, d); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitDecisionReturnsAuthenticatedReceipt(t *testing.T) {
	for _, action := range []string{"ALLOW_ONCE", "DENY"} {
		t.Run(action, func(t *testing.T) {
			a, _, server, key, r := authorityFixture(t)
			ctx := context.Background()
			decision := signedDecision(t, r.Request, key, action)
			challenge := make([]byte, 32)
			for i := range challenge {
				challenge[i] = byte(9 - i)
			}
			receipt, err := a.SubmitDecision(ctx, r.Request.RequestID, decision, challenge)
			if err != nil {
				t.Fatal(err)
			}
			devicePub := key.Public().(ed25519.PublicKey)
			serverPub := server.Public().(ed25519.PublicKey)
			if err := approval.VerifyDecisionReceipt(r.Request, decision, receipt, challenge, devicePub, serverPub, time.Unix(1000, 0)); err != nil {
				t.Fatal(err)
			}
			want := "AUTHORIZED"
			if action == "DENY" {
				want = "DENIED"
			}
			if receipt.Receipt.Status != want {
				t.Fatalf("status=%s want=%s", receipt.Receipt.Status, want)
			}
			if _, err := a.SubmitDecision(ctx, r.Request.RequestID, decision, challenge); err == nil {
				t.Fatal("replayed decision accepted")
			}
		})
	}
}

func TestSubmitDecisionRejectsInvalidChallengeBeforeConsumption(t *testing.T) {
	a, _, _, key, r := authorityFixture(t)
	decision := signedDecision(t, r.Request, key, "ALLOW_ONCE")
	if _, err := a.SubmitDecision(context.Background(), r.Request.RequestID, decision, make([]byte, 31)); err == nil {
		t.Fatal("short challenge accepted")
	}
	if _, status, err := a.Request(context.Background(), r.Request.RequestID); err != nil || status != "PENDING_APPROVAL" {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

func TestDecisionLookupRecoversLostReceiptWithoutExecution(t *testing.T) {
	a, db, server, key, r := authorityFixture(t)
	ctx := context.Background()
	q, err := approval.NewDecisionLookup("server", "desktop", r.Request, time.Unix(1300, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedLookup, err := approval.SignDecisionLookup(q, key)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := a.LookupDecision(ctx, signedLookup)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDecisionLookupResult(q, pending, server.Public().(ed25519.PublicKey), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if !pending.Result.Found || pending.Result.Status != "PENDING_APPROVAL" || pending.Result.DecisionAction != "" {
		t.Fatalf("pending=%+v", pending.Result)
	}
	decision := signedDecision(t, r.Request, key, "ALLOW_ONCE")
	// Deliberately discard the receipt to model delivery loss after commit.
	if _, err := a.SubmitDecision(ctx, r.Request.RequestID, decision, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	recovered, err := a.LookupDecision(ctx, signedLookup)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDecisionLookupResult(q, recovered, server.Public().(ed25519.PublicKey), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if !recovered.Result.Found || recovered.Result.Status != "AUTHORIZED" || recovered.Result.DecisionAction != "ALLOW_ONCE" || recovered.Result.DecisionDeviceID != "desktop" {
		t.Fatalf("recovered=%+v", recovered.Result)
	}
	if _, err := a.Execute(ctx, r.Request.RequestID, func(context.Context, approval.Request) executor.Result {
		return executor.Result{Status: "SUCCEEDED"}
	}); err != nil {
		t.Fatal(err)
	}
	completed, err := a.LookupDecision(ctx, signedLookup)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Result.Status != "SUCCEEDED" || completed.Result.DecisionAction != "ALLOW_ONCE" {
		t.Fatalf("completed=%+v", completed.Result)
	}
	if _, err := a.SubmitDecision(ctx, r.Request.RequestID, decision, make([]byte, 32)); err == nil {
		t.Fatal("recovery lookup repeated decision")
	}
	var executions int
	if err := db.QueryRow("SELECT count(*) FROM authority_executions").Scan(&executions); err != nil {
		t.Fatal(err)
	}
	if executions != 1 {
		t.Fatalf("executions=%d", executions)
	}
}

func TestDecisionLookupNotFoundIsAuthenticatedAndIsolated(t *testing.T) {
	a, _, server, _, _ := authorityFixture(t)
	ctx := context.Background()
	pub, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollTrusted(ctx, "other", pub); err != nil {
		t.Fatal(err)
	}
	req, err := approval.NewRequest("server", "missing", "agent", "session", []byte(`{"type":"cmd.run"}`))
	if err != nil {
		t.Fatal(err)
	}
	q, err := approval.NewDecisionLookup("server", "other", req, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignDecisionLookup(q, other)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.LookupDecision(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDecisionLookupResult(q, result, server.Public().(ed25519.PublicKey), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if result.Result.Found || result.Result.Request != nil || result.Result.Status != "" {
		t.Fatalf("unknown result=%+v", result.Result)
	}
	signed.Lookup.DeviceID = "desktop"
	if _, err := a.LookupDecision(ctx, signed); err == nil {
		t.Fatal("impersonated lookup accepted")
	}
}

func TestDecisionLookupRejectsRevokedExpiredOrWrongDigest(t *testing.T) {
	a, _, _, key, r := authorityFixture(t)
	ctx := context.Background()
	q, err := approval.NewDecisionLookup("server", "desktop", r.Request, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignDecisionLookup(q, key)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(1100, 0) }
	if _, err := a.LookupDecision(ctx, signed); err == nil {
		t.Fatal("expired lookup accepted")
	}
	a.now = func() time.Time { return time.Unix(1000, 0) }
	if err := a.RevokeTrusted(ctx, "desktop"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.LookupDecision(ctx, signed); err == nil {
		t.Fatal("revoked device lookup accepted")
	}
	if err := a.EnrollTrusted(ctx, "desktop", key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	q.RequestSHA256 = strings.Repeat("0", 64)
	tampered, err := approval.SignDecisionLookup(q, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.LookupDecision(ctx, tampered); err == nil {
		t.Fatal("wrong request digest accepted")
	}
}

func TestAuthorityConflictingDecisions(t *testing.T) {
	a, _, _, key, r := authorityFixture(t)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, action := range []string{"ALLOW_ONCE", "DENY"} {
		d := signedDecision(t, r.Request, key, action)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.Consume(context.Background(), r.Request.RequestID, d)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted=%d", accepted)
	}
}

func TestAuthorityIdentityAndRotation(t *testing.T) {
	a, db, server, oldKey, r := authorityFixture(t)
	ctx := context.Background()
	pub, newKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, db, "wrong-server", server, nil); err == nil {
		t.Fatal("server identity replaced")
	}
	if _, err := New(ctx, db, "server", newKey, nil); err == nil {
		t.Fatal("server key replaced")
	}
	if err := a.EnrollTrusted(ctx, "desktop", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, r.Request.RequestID, signedDecision(t, r.Request, oldKey, "ALLOW_ONCE")); err == nil {
		t.Fatal("old device key accepted after rotation")
	}
	if _, err := a.Consume(ctx, r.Request.RequestID, signedDecision(t, r.Request, newKey, "ALLOW_ONCE")); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityStoredEnvelopeTampering(t *testing.T) {
	a, db, _, key, r := authorityFixture(t)
	ctx := context.Background()
	var data string
	if err := db.QueryRow("SELECT envelope FROM authority_requests WHERE request_id=?", r.Request.RequestID).Scan(&data); err != nil {
		t.Fatal(err)
	}
	data = strings.Replace(data, `"client_id":"agent"`, `"client_id":"attacker"`, 1)
	if _, err := db.Exec("UPDATE authority_requests SET envelope=? WHERE request_id=?", data, r.Request.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Request(ctx, r.Request.RequestID); err == nil {
		t.Fatal("tampered display accepted")
	}
	if _, err := a.Consume(ctx, r.Request.RequestID, signedDecision(t, r.Request, key, "ALLOW_ONCE")); err == nil {
		t.Fatal("tampered execution envelope accepted")
	}
}
