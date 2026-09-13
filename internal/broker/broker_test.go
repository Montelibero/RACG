package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/executor"
	_ "modernc.org/sqlite"
)

func TestAuthorityClientComposesSignedAgentAndApproverMessages(t *testing.T) {
	dbPath := t.TempDir() + "/authority.db"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePub, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := authority.New(context.Background(), db, "server", serverKey, func() time.Time { return time.Unix(1000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(context.Background(), "agent", agentPub); err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollTrusted(context.Background(), "device", devicePub); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	brokerConn, authorityConn := net.Pipe()
	defer brokerConn.Close()
	defer authorityConn.Close()
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeAuthority(ctx, a, authorityConn, authorityConn) }()
	client, err := NewAuthorityClient(brokerConn)
	if err != nil {
		t.Fatal(err)
	}

	staged := []byte("immutable broker transport stdin\n")
	stagedUpload, err := approval.NewStagedUpload("server", "agent", staged, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedStagedUpload, err := approval.SignStagedUpload(stagedUpload, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.StageUpload(ctx, UploadSubmission{Upload: signedStagedUpload, Data: staged}); err != nil {
		t.Fatal(err)
	}
	operation := []byte(`{"type":"cmd.run","payload":{"argv":["/bin/cat"],"stdin_upload_id":"` + stagedUpload.UploadID + `"}}`)
	submission, err := approval.NewSubmission("server", "agent", operation, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedSubmission, err := approval.SignSubmission(submission, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	signedRequest, err := client.SubmitAgent(ctx, signedSubmission)
	if err != nil {
		t.Fatal(err)
	}
	admittedOperation := append([]byte(nil), signedRequest.Request.Operation...)
	if err := approval.VerifyRequest(signedRequest, "server", serverKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	tamperedOperation := []byte(`{"type":"cmd.run","payload":{"argv":["/bin/sh","evil"]}}`)
	signedRequest.Request.Operation = tamperedOperation
	if err := approval.VerifyRequest(signedRequest, "server", serverKey.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("broker-modified operation accepted")
	}
	signedRequest.Request.Operation = admittedOperation

	decision, err := approval.SignDecision(signedRequest.Request, "device", "ALLOW_ONCE", nil, time.Unix(1100, 0), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	receipt, err := client.SubmitDecision(ctx, DecisionSubmission{
		RequestID: signedRequest.Request.RequestID,
		Decision:  decision,
		Challenge: challenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDecisionReceipt(signedRequest.Request, decision, receipt, challenge, devicePub, serverKey.Public().(ed25519.PublicKey), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}

	result, err := a.Execute(ctx, signedRequest.Request.RequestID, func(context.Context, approval.Request) executor.Result {
		got, err := a.StagedUploadForRequest(context.Background(), signedRequest.Request, stagedUpload.UploadID)
		if err != nil {
			t.Errorf("staged upload: %v", err)
			return executor.Result{Status: "FAILED"}
		}
		if string(got) != string(staged) {
			t.Errorf("staged upload=%q", got)
			return executor.Result{Status: "FAILED"}
		}
		return executor.Result{Status: "SUCCEEDED"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "SUCCEEDED" {
		t.Fatalf("result=%+v", result)
	}

	lookup, err := approval.NewDecisionLookup("server", "device", signedRequest.Request, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedLookup, err := approval.SignDecisionLookup(lookup, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	lookupResult, err := client.LookupDecision(ctx, signedLookup)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyDecisionLookupResult(lookup, lookupResult, serverKey.Public().(ed25519.PublicKey), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if lookupResult.Result.Status != "SUCCEEDED" || lookupResult.Result.DecisionAction != "ALLOW_ONCE" {
		t.Fatalf("lookup=%+v", lookupResult.Result)
	}
	agentLookup, err := approval.NewLookup("server", "agent", submission.Nonce, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedAgentLookup, err := approval.SignLookup(agentLookup, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	agentResult, err := client.LookupSubmission(ctx, signedAgentLookup)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.VerifyLookupResult(agentLookup, agentResult, serverKey.Public().(ed25519.PublicKey), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if !agentResult.Result.Found || agentResult.Result.Status != "SUCCEEDED" || agentResult.Result.Request.Request.RequestID != signedRequest.Request.RequestID {
		t.Fatalf("agent lookup=%+v", agentResult.Result)
	}
	var raw json.RawMessage
	if err := client.call(ctx, "v1/authority.execute", nil, &raw); err == nil {
		t.Fatal("execution method accepted")
	}
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
}
