package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
)

func TestStageUploadBindsImmutableBytesToRequest(t *testing.T) {
	a, _, _, _, _ := authorityFixture(t)
	ctx := context.Background()
	agentPublic, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(ctx, "agent", agentPublic); err != nil {
		t.Fatal(err)
	}
	devicePublic, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollTrusted(ctx, "device", devicePublic); err != nil {
		t.Fatal(err)
	}
	data := []byte("immutable stdin\n")
	upload, err := approval.NewStagedUpload("server", "agent", data, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedUpload, err := approval.SignStagedUpload(upload, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.StageUpload(ctx, signedUpload, append([]byte(nil), data...)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.StageUpload(ctx, signedUpload, []byte("changed")); err == nil {
		t.Fatal("changed staged bytes accepted")
	}
	operation := `{"type":"cmd.run","payload":{"argv":["/bin/cat"],"stdin_upload_id":"` + upload.UploadID + `"}}`
	submission, err := approval.NewSubmission("server", "agent", []byte(operation), time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signedSubmission, err := approval.SignSubmission(submission, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	signedRequest, err := a.Submit(ctx, signedSubmission)
	if err != nil {
		t.Fatal(err)
	}
	var admittedEnvelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(signedRequest.Request.Operation, &admittedEnvelope); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		StdinUploadID string `json:"stdin_upload_id"`
		StdinSize     int64  `json:"stdin_size"`
		StdinSHA256   string `json:"stdin_sha256"`
	}
	if err := json.Unmarshal(admittedEnvelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.StdinUploadID != upload.UploadID || payload.StdinSize != int64(len(data)) || payload.StdinSHA256 != approval.SHA256Hex(data) {
		t.Fatalf("admitted metadata=%+v operation=%s", payload, signedRequest.Request.Operation)
	}
	second, err := approval.NewSubmission("server", "agent", []byte(operation), time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	secondSigned, err := approval.SignSubmission(second, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Submit(ctx, secondSigned); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("second claim error=%v", err)
	}
	decision, err := approval.SignDecision(signedRequest.Request, "device", "ALLOW_ONCE", nil, time.Unix(1100, 0), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Consume(ctx, signedRequest.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if _, err := a.Execute(ctx, signedRequest.Request.RequestID, func(_ context.Context, request approval.Request) executor.Result {
		calls++
		got, err := a.StagedUploadForRequest(ctx, request, payload.StdinUploadID)
		if err != nil {
			t.Errorf("staged bytes: %v", err)
		}
		if string(got) != string(data) {
			t.Errorf("staged bytes=%q", got)
		}
		return executor.Result{Status: "SUCCEEDED"}
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestAdmissionRejectsInvalidAndUnstagedOperations(t *testing.T) {
	a, _, _, _, _ := authorityFixture(t)
	ctx := context.Background()
	agentPublic, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(ctx, "agent", agentPublic); err != nil {
		t.Fatal(err)
	}
	upload, err := approval.NewStagedUpload("server", "agent", []byte("data"), time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	validID := upload.UploadID
	operations := map[string]string{
		"unknown type":       `{"type":"rm.rf","payload":{}}`,
		"unknown field":      `{"type":"cmd.run","payload":{"argv":["/bin/echo"],"evil":"yes"}}`,
		"empty argv":         `{"type":"cmd.run","payload":{"argv":[]}}`,
		"negative timeout":   `{"type":"cmd.run","payload":{"argv":["/bin/echo"],"timeout_sec":-1}}`,
		"client metadata":    `{"type":"cmd.run","payload":{"argv":["/bin/cat"],"stdin_upload_id":"` + validID + `","stdin_size":4}}`,
		"missing upload":     `{"type":"fs.upload","payload":{"path":"/tmp/target","upload_id":"` + strings.Repeat("0", 32) + `"}}`,
		"missing patch":      `{"type":"fs.patch_unified","payload":{"path":"/tmp/target"}}`,
		"bad config value":   `{"type":"conf.set","payload":{"path":"/tmp/app.conf","format":"env","key":"X","value_type":"command"}}`,
		"unknown download":   `{"type":"fs.download","payload":{"path":""}}`,
		"outer unknown":      `{"type":"fs.read","payload":{"path":"/tmp/x"},"broker_status":"approved"}`,
		"unstaged stdin":     `{"type":"cmd.run","payload":{"argv":["/bin/cat"],"stdin_upload_id":"` + validID + `"}}`,
		"fs upload unstaged": `{"type":"fs.upload","payload":{"path":"/tmp/target","upload_id":"` + validID + `"}}`,
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			submission, err := approval.NewSubmission("server", "agent", []byte(operation), time.Unix(1100, 0))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := approval.SignSubmission(submission, agentKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.Submit(ctx, signed); err == nil {
				t.Fatal("invalid operation accepted")
			}
		})
	}
}
