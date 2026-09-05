package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

func agentSubmission(t *testing.T, a *Authority) (approval.SignedSubmission, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(context.Background(), "agent", pub); err != nil {
		t.Fatal(err)
	}
	s, err := approval.NewSubmission("server", "agent", []byte(`{"type":"cmd.run","payload":{"argv":["echo","hello"]}}`), time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignSubmission(s, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, key
}

func TestAgentEnrollmentAndRetrySurviveRestart(t *testing.T) {
	a, db, server, _, _ := authorityFixture(t)
	ctx := context.Background()
	submission, _ := agentSubmission(t, a)
	first, err := a.Submit(ctx, submission)
	if err != nil {
		t.Fatal(err)
	}
	var seq int
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	reopened, err := New(ctx, fresh, "server", server, func() time.Time { return time.Unix(1001, 0) })
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.Submit(ctx, submission)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Request.RequestID != first.Request.RequestID || string(retry.Signature) != string(first.Signature) {
		t.Fatal("retry created a new request")
	}
	if retry.Request.ClientID != "agent" || retry.Request.SessionID != "" {
		t.Fatalf("identity=%+v", retry.Request)
	}
	_, status, err := reopened.Request(ctx, first.Request.RequestID)
	if err != nil || status != "PENDING_APPROVAL" {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

func TestAgentCannotApprove(t *testing.T) {
	a, _, _, _, _ := authorityFixture(t)
	s, key := agentSubmission(t, a)
	r, err := a.Submit(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"agent", "desktop"} {
		d, err := approval.SignDecision(r.Request, id, "ALLOW_ONCE", nil, time.Unix(1100, 0), key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Consume(context.Background(), r.Request.RequestID, d); err == nil {
			t.Fatalf("agent approved as %s", id)
		}
	}
}

func TestAgentSubmissionRejectsForgeryRevocationAndExpiry(t *testing.T) {
	for _, attack := range []string{"client", "server", "operation", "nonce", "expiry", "version", "signature", "revoked", "rotated", "expired"} {
		t.Run(attack, func(t *testing.T) {
			a, _, _, _, _ := authorityFixture(t)
			s, key := agentSubmission(t, a)
			ctx := context.Background()
			switch attack {
			case "client":
				s.Submission.ClientID = "other"
			case "server":
				s.Submission.ServerID = "other"
			case "operation":
				s.Submission.Operation = []byte(`{"argv":["rm"]}`)
			case "nonce":
				s.Submission.Nonce[0] ^= 1
			case "expiry":
				s.Submission.ValidUntil = time.Unix(1200, 0).UTC().Format(time.RFC3339Nano)
			case "version":
				s.Submission.Version++
			case "signature":
				s.Signature[0] ^= 1
			case "revoked":
				if err := a.RevokeAgentTrusted(ctx, "agent"); err != nil {
					t.Fatal(err)
				}
			case "rotated":
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := a.EnrollAgentTrusted(ctx, "agent", pub); err != nil {
					t.Fatal(err)
				}
			case "expired":
				s.Submission.ValidUntil = time.Unix(1000, 0).UTC().Format(time.RFC3339Nano)
				var err error
				s, err = approval.SignSubmission(s.Submission, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.Submit(ctx, s); err == nil {
				t.Fatal("untrusted submission accepted")
			}
			var count int
			if err := a.db.QueryRow("SELECT count(*) FROM authority_submissions").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("failed admission persisted")
			}
		})
	}
}

func TestAgentNonceCannotChangeOperation(t *testing.T) {
	a, _, _, _, _ := authorityFixture(t)
	s, key := agentSubmission(t, a)
	ctx := context.Background()
	if _, err := a.Submit(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Submission.Operation = []byte(`{"argv":["different"]}`)
	changed, err := approval.SignSubmission(s.Submission, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Submit(ctx, changed); err == nil {
		t.Fatal("nonce reused for another operation")
	}
}

func TestConcurrentSubmissionRetriesCreateOneRequest(t *testing.T) {
	a, _, _, _, _ := authorityFixture(t)
	s, _ := agentSubmission(t, a)
	ids := make(chan string, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := a.Submit(context.Background(), s)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- r.Request.RequestID
		}()
	}
	wg.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		} else if id != first {
			t.Fatal("duplicate request")
		}
	}
	var count int
	if err := a.db.QueryRow("SELECT count(*) FROM authority_submissions").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("submissions=%d", count)
	}
}

func TestAgentAdmissionRollback(t *testing.T) {
	a, db, _, _, _ := authorityFixture(t)
	s, _ := agentSubmission(t, a)
	ctx := context.Background()
	if _, err := db.Exec("CREATE TRIGGER fail_nonce BEFORE INSERT ON authority_submissions BEGIN SELECT RAISE(ABORT,'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Submit(ctx, s); err == nil {
		t.Fatal("ignored storage failure")
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM authority_requests").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("admission left orphaned pending request")
	}
	if _, err := db.Exec("DROP TRIGGER fail_nonce"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Submit(ctx, s); err != nil {
		t.Fatal(err)
	}
}
