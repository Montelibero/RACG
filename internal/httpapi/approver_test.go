package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/store"
)

type approverTestDevice struct {
	id     string
	priv   *ecdsa.PrivateKey
	pubDER []byte
}

func newApproverTestDevice(t *testing.T, id string) *approverTestDevice {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &approverTestDevice{id: id, priv: priv, pubDER: pubDER}
}

func (d *approverTestDevice) sign(t *testing.T, message []byte) []byte {
	t.Helper()
	hash := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, d.priv, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func newApproverTestAPI(t *testing.T) (*API, *store.Store, string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertSession(ctx, store.Session{ID: "session", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tokens := auth.NewTokenManager(nil)
	token, _ := tokens.Issue("session", "client", time.Hour)
	called := make(chan struct{}, 4)
	api := New(config.Defaults(), WithStore(st), WithTokenManager(tokens), WithExecutor(decisionProbeRunner{called}))
	return api, st, token
}

func createPendingApproverRequest(t *testing.T, api *API, agentToken string) ApproverRequest {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/requests",
		strings.NewReader(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hello"]}}}`))
	req.Header.Set("Authorization", "Bearer "+agentToken)
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code > 300 {
		t.Fatalf("request creation failed: %d %s", rw.Code, rw.Body.String())
	}
	pending := api.PendingForApprover()
	if len(pending) != 1 {
		t.Fatalf("pending count = %d, want 1", len(pending))
	}
	return pending[0]
}

func fetchApproverChallenge(t *testing.T, api *API) string {
	t.Helper()
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/v1/approver/challenge", nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rw.Code, rw.Body.String())
	}
	var out struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Challenge
}

func (d *approverTestDevice) pairRequest(t *testing.T, api *API, serverID, tokenHex string) *http.Request {
	t.Helper()
	challenge := fetchApproverChallenge(t, api)
	pubHash := sha256.Sum256(d.pubDER)
	message := approverMessage(approverPairingDomain, serverID, d.id, hex.EncodeToString(pubHash[:]), challenge, tokenHex)
	body, err := json.Marshal(approverPairingRequest{
		DeviceID:    d.id,
		PublicKey:   d.pubDER,
		TokenSHA256: tokenHex,
		Challenge:   challenge,
		Signature:   d.sign(t, message),
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPost, "/v1/approver/pairing", strings.NewReader(string(body)))
}

func (d *approverTestDevice) pollRequest(t *testing.T, api *API, path string) *http.Request {
	t.Helper()
	challenge := fetchApproverChallenge(t, api)
	message := approverMessage(approverPollDomain, api.serverName, d.id, path, challenge)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(approverHeaderDevice, d.id)
	req.Header.Set(approverHeaderChallenge, challenge)
	req.Header.Set(approverHeaderSignature, base64.StdEncoding.EncodeToString(d.sign(t, message)))
	return req
}

func (d *approverTestDevice) decisionRequest(t *testing.T, api *API, serverID, requestID, opSHA256, decision string) *http.Request {
	t.Helper()
	challenge := fetchApproverChallenge(t, api)
	message := approverMessage(approverDecisionDomain, serverID, d.id, requestID, opSHA256, decision, challenge)
	body, err := json.Marshal(approverDecisionRequest{
		DeviceID:        d.id,
		RequestID:       requestID,
		Decision:        decision,
		OperationSHA256: opSHA256,
		Challenge:       challenge,
		Signature:       d.sign(t, message),
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPost, "/v1/approver/decision", strings.NewReader(string(body)))
}

func serveApprover(t *testing.T, api *API, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, r)
	return rw
}

func approverTokenHex(api *API) string {
	sum := sha256.Sum256(api.approverTokenBytes())
	return hex.EncodeToString(sum[:])
}

func TestApproverPairingPollDecisionFlow(t *testing.T) {
	api, st, agentToken := newApproverTestAPI(t)
	pending := createPendingApproverRequest(t, api, agentToken)
	device := newApproverTestDevice(t, "dev1")

	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}

	rw := serveApprover(t, api, device.pollRequest(t, api, "/v1/approver/requests"))
	if rw.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", rw.Code, rw.Body.String())
	}
	var list struct {
		Requests []ApproverRequest `json:"requests"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Requests) != 1 || list.Requests[0].ID != pending.ID || list.Requests[0].OpSHA256 != pending.OpSHA256 {
		t.Fatalf("poll body: %s", rw.Body.String())
	}

	if rw := serveApprover(t, api, device.pollRequest(t, api, "/v1/approver/requests/"+pending.ID)); rw.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", rw.Code, rw.Body.String())
	}

	if rw := serveApprover(t, api, device.decisionRequest(t, api, api.serverName, pending.ID, pending.OpSHA256, "ALLOW_ONCE")); rw.Code != http.StatusOK {
		t.Fatalf("decision: %d %s", rw.Code, rw.Body.String())
	}
	if left := api.PendingForApprover(); len(left) != 0 {
		t.Fatalf("request still pending after decision")
	}
	saved, err := st.GetDecision(context.Background(), pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Decision != "ALLOW_ONCE" || saved.DecisionSource != "approver:dev1" {
		t.Fatalf("saved decision: %+v", saved)
	}
}

func TestApproverChallengeIsSingleUse(t *testing.T) {
	api, _, agentToken := newApproverTestAPI(t)
	createPendingApproverRequest(t, api, agentToken)
	device := newApproverTestDevice(t, "dev1")

	// Pairing burns its challenge: an immediate replay is rejected.
	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}
	replay := device.pollRequest(t, api, "/v1/approver/requests")
	first := serveApprover(t, api, replay)
	if first.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", first.Code, first.Body.String())
	}
	// Same signed request replayed: challenge already consumed.
	if rw := serveApprover(t, api, replay); rw.Code != http.StatusUnauthorized {
		t.Fatalf("replayed poll: %d %s", rw.Code, rw.Body.String())
	}
}

func TestApproverUnenrolledAndForgedKeysRejected(t *testing.T) {
	api, _, agentToken := newApproverTestAPI(t)
	pending := createPendingApproverRequest(t, api, agentToken)
	enrolled := newApproverTestDevice(t, "dev1")
	foreign := newApproverTestDevice(t, "dev2")

	if rw := serveApprover(t, api, enrolled.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}

	// Unenrolled device cannot poll or decide.
	if rw := serveApprover(t, api, foreign.pollRequest(t, api, "/v1/approver/requests")); rw.Code != http.StatusUnauthorized {
		t.Fatalf("unenrolled poll: %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveApprover(t, api, foreign.decisionRequest(t, api, api.serverName, pending.ID, pending.OpSHA256, "ALLOW_ONCE")); rw.Code != http.StatusUnauthorized {
		t.Fatalf("unenrolled decision: %d %s", rw.Code, rw.Body.String())
	}

	// Forged identity: foreign key signs a decision claiming to be dev1.
	challenge := fetchApproverChallenge(t, api)
	message := approverMessage(approverDecisionDomain, api.serverName, "dev1", pending.ID, pending.OpSHA256, "ALLOW_ONCE", challenge)
	body, err := json.Marshal(approverDecisionRequest{
		DeviceID:        "dev1",
		RequestID:       pending.ID,
		Decision:        "ALLOW_ONCE",
		OperationSHA256: pending.OpSHA256,
		Challenge:       challenge,
		Signature:       foreign.sign(t, message),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rw := serveApprover(t, api, httptest.NewRequest(http.MethodPost, "/v1/approver/decision", strings.NewReader(string(body)))); rw.Code != http.StatusUnauthorized {
		t.Fatalf("forged decision: %d %s", rw.Code, rw.Body.String())
	}
	if left := api.PendingForApprover(); len(left) != 1 {
		t.Fatalf("forged decision executed the request")
	}
}

func TestApproverRevokedDeviceRejectedUntilReEnabled(t *testing.T) {
	api, st, agentToken := newApproverTestAPI(t)
	pending := createPendingApproverRequest(t, api, agentToken)
	device := newApproverTestDevice(t, "dev1")
	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}

	if err := st.SetApproverDeviceEnabled(context.Background(), "dev1", false, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if rw := serveApprover(t, api, device.pollRequest(t, api, "/v1/approver/requests")); rw.Code != http.StatusUnauthorized {
		t.Fatalf("revoked poll: %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveApprover(t, api, device.decisionRequest(t, api, api.serverName, pending.ID, pending.OpSHA256, "ALLOW_ONCE")); rw.Code != http.StatusUnauthorized {
		t.Fatalf("revoked decision: %d %s", rw.Code, rw.Body.String())
	}

	if err := st.SetApproverDeviceEnabled(context.Background(), "dev1", true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if rw := serveApprover(t, api, device.decisionRequest(t, api, api.serverName, pending.ID, pending.OpSHA256, "DENY")); rw.Code != http.StatusOK {
		t.Fatalf("re-enabled decision: %d %s", rw.Code, rw.Body.String())
	}
}

func TestApproverWrongServerRejected(t *testing.T) {
	api, _, agentToken := newApproverTestAPI(t)
	pending := createPendingApproverRequest(t, api, agentToken)
	device := newApproverTestDevice(t, "dev1")

	if rw := serveApprover(t, api, device.pairRequest(t, api, "some-other-server", approverTokenHex(api))); rw.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-server pairing: %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}
	if rw := serveApprover(t, api, device.decisionRequest(t, api, "some-other-server", pending.ID, pending.OpSHA256, "ALLOW_ONCE")); rw.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-server decision: %d %s", rw.Code, rw.Body.String())
	}
	if left := api.PendingForApprover(); len(left) != 1 {
		t.Fatalf("wrong-server decision executed the request")
	}
}

func TestApproverDecisionBindsExactOperation(t *testing.T) {
	api, _, agentToken := newApproverTestAPI(t)
	pending := createPendingApproverRequest(t, api, agentToken)
	device := newApproverTestDevice(t, "dev1")
	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}

	forgedDigest := hex.EncodeToString([]byte("00000000000000000000000000000000"))
	rw := serveApprover(t, api, device.decisionRequest(t, api, api.serverName, pending.ID, forgedDigest, "ALLOW_ONCE"))
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), "OPERATION_MISMATCH") {
		t.Fatalf("digest mismatch: %d %s", rw.Code, rw.Body.String())
	}
	if left := api.PendingForApprover(); len(left) != 1 {
		t.Fatalf("mismatched decision executed the request")
	}
}

func TestApproverPairingRejectsWrongTokenAndUnsignedPolls(t *testing.T) {
	api, _, agentToken := newApproverTestAPI(t)
	createPendingApproverRequest(t, api, agentToken)
	device := newApproverTestDevice(t, "dev1")

	wrongToken := hex.EncodeToString([]byte("not-the-token"))
	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, wrongToken)); rw.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token pairing: %d %s", rw.Code, rw.Body.String())
	}

	if rw := serveApprover(t, api, httptest.NewRequest(http.MethodGet, "/v1/approver/requests", nil)); rw.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned poll: %d %s", rw.Code, rw.Body.String())
	}
	// A valid pairing still works afterwards: the failed attempts must not
	// have burned the enrollment token.
	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}
}

func TestApproverSecondDecisionAfterApprovalRejected(t *testing.T) {
	api, _, agentToken := newApproverTestAPI(t)
	pending := createPendingApproverRequest(t, api, agentToken)
	device := newApproverTestDevice(t, "dev1")
	if rw := serveApprover(t, api, device.pairRequest(t, api, api.serverName, approverTokenHex(api))); rw.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rw.Code, rw.Body.String())
	}

	if rw := serveApprover(t, api, device.decisionRequest(t, api, api.serverName, pending.ID, pending.OpSHA256, "ALLOW_ONCE")); rw.Code != http.StatusOK {
		t.Fatalf("first decision: %d %s", rw.Code, rw.Body.String())
	}
	rw := serveApprover(t, api, device.decisionRequest(t, api, api.serverName, pending.ID, pending.OpSHA256, "DENY"))
	if rw.Code != http.StatusNotFound || !strings.Contains(rw.Body.String(), "REQUEST_NOT_FOUND") {
		t.Fatalf("conflicting decision: %d %s", rw.Code, rw.Body.String())
	}
}
