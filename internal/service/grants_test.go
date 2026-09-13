package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
	"github.com/itolstov/racg/internal/rules"
)

func TestServiceGrantsAutoAuthorizeAndExecute(t *testing.T) {
	service, config, _ := adminServiceFixture(t)
	defer service.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.Run(ctx) }()

	admin, closeAdmin, err := ConnectAdmin(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	agentPublic, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.RotateAgent(ctx, "agent", agentPublic); err != nil {
		t.Fatal(err)
	}
	if err := admin.RotateDevice(ctx, "device", devicePublic); err != nil {
		t.Fatal(err)
	}
	brokerClient, closeBroker, err := ConnectBroker(ctx, brokerConfigForAdmin(config))
	if err != nil {
		t.Fatal(err)
	}
	operation := []byte(`{"type":"cmd.run","payload":{"argv":["/bin/echo","service-grant"]}}`)
	submission, err := approval.NewSubmission("server", "agent", operation, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedSubmission, err := approval.SignSubmission(submission, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	request, err := brokerClient.SubmitAgent(ctx, signedSubmission)
	if err != nil {
		t.Fatal(err)
	}
	scopeData, err := json.Marshal(authority.GrantScope{
		Version:  approval.Version,
		ClientID: "agent",
		Rule: rules.Rule{
			ID:     "service-echo",
			OpType: "cmd.run",
			Cmd:    &rules.CmdRule{ArgvPrefix: []string{"/bin/echo", "service-grant"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := approval.Grant{
		Scope:     scopeData,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	}
	decision, err := approval.SignDecision(request.Request, "device", "ALLOW_UNTIL", &grant, time.Now().Add(time.Minute), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := brokerClient.SubmitDecision(ctx, broker.DecisionSubmission{
		RequestID: request.Request.RequestID,
		Decision:  decision,
		Challenge: make([]byte, 32),
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, executionStatus, err := service.Authority().Request(ctx, request.Request.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if executionStatus != "AUTHORIZED" {
			break
		}
		if time.Now().After(deadline) {
			result, executeErr := service.Authority().ExecuteStored(ctx, request.Request.RequestID, config.Execution.Options())
			t.Fatalf("dispatch did not start: status=%s result=%+v executeErr=%v supervisorErr=%v", executionStatus, result, executeErr, service.executions.executionError())
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitForAgentLookup(t, ctx, brokerClient, agentKey, serverPublicKey(service), submission.Nonce, "SUCCEEDED", "service-grant\n")

	matching, err := approval.NewSubmission("server", "agent", operation, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedMatching, err := approval.SignSubmission(matching, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	matchingRequest, err := brokerClient.SubmitAgent(ctx, signedMatching)
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		_, executionStatus, err := service.Authority().Request(ctx, matchingRequest.Request.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if executionStatus != "AUTHORIZED" {
			break
		}
		if time.Now().After(deadline) {
			result, executeErr := service.Authority().ExecuteStored(ctx, matchingRequest.Request.RequestID, config.Execution.Options())
			t.Fatalf("matching dispatch did not start: status=%s result=%+v executeErr=%v supervisorErr=%v",
				executionStatus, result, executeErr, service.executions.executionError())
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitForAgentLookup(t, ctx, brokerClient, agentKey, serverPublicKey(service), matching.Nonce, "SUCCEEDED", "service-grant\n")

	grants, err := admin.ListGrants(ctx)
	if err != nil || len(grants) == 0 {
		t.Fatalf("grants=%+v err=%v", grants, err)
	}
	if err := admin.RevokeGrant(ctx, grants[0].ID); err != nil {
		t.Fatal(err)
	}
	third, err := approval.NewSubmission("server", "agent", operation, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedThird, err := approval.SignSubmission(third, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	thirdRequest, err := brokerClient.SubmitAgent(ctx, signedThird)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := approval.NewLookup("server", "agent", third.Nonce, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signedLookup, err := approval.SignLookup(lookup, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	lookupResult, err := brokerClient.LookupSubmission(ctx, signedLookup)
	if err != nil {
		t.Fatal(err)
	}
	if lookupResult.Result.Status != "PENDING_APPROVAL" {
		t.Fatalf("revoked grant status=%s", lookupResult.Result.Status)
	}
	_ = thirdRequest
	closeBroker()
	closeAdmin()
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service did not stop")
	}
}

func waitForAgentLookup(t *testing.T, ctx context.Context, client *broker.AuthorityClient, agentKey ed25519.PrivateKey, serverKey ed25519.PublicKey, nonce []byte, status, stdout string) {
	t.Helper()
	lookup, err := approval.NewLookup("server", "agent", nonce, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignLookup(lookup, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		result, err := client.LookupSubmission(ctx, signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := approval.VerifyLookupResult(lookup, result, serverKey, time.Now()); err != nil {
			t.Fatal(err)
		}
		if result.Result.Status == status {
			if stdout != "" && (result.Result.Result == nil || result.Result.Result.Stdout != stdout) {
				t.Fatalf("result=%+v", result.Result)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lookup status=%s want=%s", result.Result.Status, status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func serverPublicKey(service *AuthorityService) ed25519.PublicKey {
	return service.PublicKey()
}
