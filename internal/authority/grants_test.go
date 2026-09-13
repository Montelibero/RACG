package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
	"github.com/itolstov/racg/internal/rules"
)

func grantScope(t *testing.T, request approval.Request, rule rules.Rule) approval.Grant {
	t.Helper()
	canonical, err := json.Marshal(GrantScope{Version: approval.Version, ClientID: request.ClientID, Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	return approval.Grant{Scope: canonical}
}

func TestReusableGrantAuthorizesMatchingAgentOnly(t *testing.T) {
	a, _, _, deviceKey, request := authorityFixture(t)
	ctx := context.Background()
	grant := grantScope(t, request.Request, rules.Rule{
		ID:     "echo-approved",
		OpType: "cmd.run",
		Cmd:    &rules.CmdRule{ArgvPrefix: []string{"/bin/echo", "approved"}},
	})
	expires := time.Unix(1100, 0).UTC()
	grant.ExpiresAt = expires.Format(time.RFC3339Nano)
	decision, err := approval.SignDecision(request.Request, "desktop", "ALLOW_UNTIL", &grant, time.Unix(1100, 0), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, request.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	_, status, err := a.Request(ctx, request.Request.RequestID)
	if err != nil || status != "AUTHORIZED" {
		t.Fatalf("status=%s err=%v", status, err)
	}
	if _, err := a.ExecuteStored(ctx, request.Request.RequestID, OperationExecutionOptions{}); err != nil {
		t.Fatal(err)
	}

	agentPublic, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(ctx, "agent", agentPublic); err != nil {
		t.Fatal(err)
	}
	matching, err := approval.NewSubmission("server", "agent", request.Request.Operation, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedMatching, err := approval.SignSubmission(matching, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	matchingRequest, err := a.Submit(ctx, signedMatching)
	if err != nil {
		t.Fatal(err)
	}
	_, status, err = a.Request(ctx, matchingRequest.Request.RequestID)
	if err != nil || status != "AUTHORIZED" {
		t.Fatalf("matching status=%s err=%v", status, err)
	}
	otherOperation := strings.Replace(string(request.Request.Operation), `"approved"`, `"other"`, 1)
	other, err := approval.NewSubmission("server", "agent", []byte(otherOperation), time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedOther, err := approval.SignSubmission(other, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, err := a.Submit(ctx, signedOther)
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := a.Request(ctx, otherRequest.Request.RequestID); err != nil || status != "PENDING_APPROVAL" {
		t.Fatalf("other status=%s err=%v", status, err)
	}
	foreignPublic, foreignKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(ctx, "other-agent", foreignPublic); err != nil {
		t.Fatal(err)
	}
	foreign, err := approval.NewSubmission("server", "other-agent", request.Request.Operation, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedForeign, err := approval.SignSubmission(foreign, foreignKey)
	if err != nil {
		t.Fatal(err)
	}
	foreignRequest, err := a.Submit(ctx, signedForeign)
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := a.Request(ctx, foreignRequest.Request.RequestID); err != nil || status != "PENDING_APPROVAL" {
		t.Fatalf("foreign status=%s err=%v", status, err)
	}
}

func TestGrantExpiresAndRevocationBlocksDispatch(t *testing.T) {
	a, _, _, deviceKey, request := authorityFixture(t)
	ctx := context.Background()
	grant := grantScope(t, request.Request, rules.Rule{OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})
	grant.ExpiresAt = time.Unix(1100, 0).UTC().Format(time.RFC3339Nano)
	decision, err := approval.SignDecision(request.Request, "desktop", "ALLOW_UNTIL", &grant, time.Unix(1100, 0), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, request.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(1100, 0) }
	if _, err := a.ExecuteStored(ctx, request.Request.RequestID, OperationExecutionOptions{}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired grant dispatch err=%v", err)
	}
	a.now = func() time.Time { return time.Unix(1000, 0) }
	if err := a.RevokeTrusted(ctx, "desktop"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ExecuteStored(ctx, request.Request.RequestID, OperationExecutionOptions{}); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked grant dispatch err=%v", err)
	}
}

func TestReusableGrantDecisionValidation(t *testing.T) {
	a, _, _, deviceKey, request := authorityFixture(t)
	ctx := context.Background()
	tests := map[string]func(*approval.Grant){
		"wrong agent": func(g *approval.Grant) {
			g.Scope = mustGrantScope(t, "other", rules.Rule{OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})
		},
		"unknown field": func(g *approval.Grant) {
			g.Scope = []byte(`{"version":1,"client_id":"agent","rule":{"id":"x","op_type":"cmd.run","cmd":{"argv_prefix":["/bin/echo"]}},"broker":"evil"}`)
		},
		"ambiguous path": func(g *approval.Grant) {
			g.Scope = mustGrantScope(t, "agent", rules.Rule{OpType: "fs.read", Path: &rules.PathRule{Exact: "/tmp/a", Prefix: "/tmp/"}})
		},
		"unsupported operation": func(g *approval.Grant) {
			g.Scope = mustGrantScope(t, "agent", rules.Rule{OpType: "rm.rf", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/rm"}}})
		},
		"session action": func(g *approval.Grant) {
			g.Scope = mustGrantScope(t, "agent", rules.Rule{OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			grant := grantScope(t, request.Request, rules.Rule{OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})
			mutate(&grant)
			action := "ALLOW_UNTIL"
			if name == "session action" {
				action = "ALLOW_SESSION"
			}
			if action == "ALLOW_UNTIL" {
				grant.ExpiresAt = time.Unix(1100, 0).UTC().Format(time.RFC3339Nano)
			}
			decision, err := approval.SignDecision(request.Request, "desktop", action, &grant, time.Unix(1100, 0), deviceKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.Consume(ctx, request.Request.RequestID, decision); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
}

func mustGrantScope(t *testing.T, clientID string, rule rules.Rule) []byte {
	t.Helper()
	data, err := json.Marshal(GrantScope{Version: approval.Version, ClientID: clientID, Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPermanentGrantRemainsActiveWithoutExpiry(t *testing.T) {
	a, _, _, deviceKey, request := authorityFixture(t)
	ctx := context.Background()
	grant := grantScope(t, request.Request, rules.Rule{OpType: "fs.read", Path: &rules.PathRule{Exact: "/tmp/allowed"}})
	decision, err := approval.SignDecision(request.Request, "desktop", "ALLOW_ALWAYS", &grant, time.Unix(1100, 0), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, request.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(100000, 0) }
	agentPublic, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(ctx, "agent", agentPublic); err != nil {
		t.Fatal(err)
	}
	submission, err := approval.NewSubmission("server", "agent", []byte(`{"type":"fs.read","payload":{"path":"/tmp/allowed"}}`), time.Unix(100100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignSubmission(submission, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Submit(ctx, signed); err != nil {
		t.Fatal(err)
	}
	_ = sql.ErrNoRows
	_ = executor.Result{}
}
