package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
)

func agentOperationFixture(t *testing.T, a *Authority, operation string) approval.SignedRequest {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(context.Background(), "agent", public); err != nil {
		t.Fatal(err)
	}
	submission, err := approval.NewSubmission("server", "agent", []byte(operation), time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignSubmission(submission, private)
	if err != nil {
		t.Fatal(err)
	}
	request, err := a.Submit(context.Background(), signed)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func approveAndExecuteStored(t *testing.T, a *Authority, deviceKey ed25519.PrivateKey, request approval.SignedRequest, options OperationExecutionOptions) executor.Result {
	t.Helper()
	decision := signedDecision(t, request.Request, deviceKey, "ALLOW_ONCE")
	if _, err := a.Consume(context.Background(), request.Request.RequestID, decision); err != nil {
		t.Fatal(err)
	}
	result, err := a.ExecuteStored(context.Background(), request.Request.RequestID, options)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func stagedUploadFixture(t *testing.T, a *Authority, data []byte) (approval.StagedUpload, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnrollAgentTrusted(context.Background(), "agent", public); err != nil {
		t.Fatal(err)
	}
	upload, err := approval.NewStagedUpload("server", "agent", data, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignStagedUpload(upload, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.StageUpload(context.Background(), signed, data); err != nil {
		t.Fatal(err)
	}
	return upload, private
}

func TestExecuteStoredCommandUsesImmutableStagedStdin(t *testing.T) {
	a, _, _, deviceKey, _ := authorityFixture(t)
	data := []byte("executor staged stdin\n")
	upload, _ := stagedUploadFixture(t, a, data)
	request := agentOperationFixture(t, a, `{"type":"cmd.run","payload":{"argv":["/bin/cat"],"stdin_upload_id":"`+upload.UploadID+`"}}`)
	result := approveAndExecuteStored(t, a, deviceKey, request, OperationExecutionOptions{})
	if result.Status != "SUCCEEDED" || result.Stdout != string(data) {
		t.Fatalf("result=%+v", result)
	}
	if _, err := a.StagedUploadForRequest(context.Background(), request.Request, upload.UploadID); err == nil {
		t.Fatal("successful execution retained staged stdin")
	}
}

func TestExecuteStoredReadPatchConfigUploadDownload(t *testing.T) {
	a, _, _, deviceKey, _ := authorityFixture(t)
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	target := filepath.Join(root, "target.txt")
	config := filepath.Join(root, "app.env")
	patched := filepath.Join(root, "patched.txt")
	if err := os.WriteFile(source, []byte("download secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patched, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	readRequest := agentOperationFixture(t, a, `{"type":"fs.read","payload":{"path":"`+source+`","max_bytes":10}}`)
	readResult := approveAndExecuteStored(t, a, deviceKey, readRequest, OperationExecutionOptions{})
	if readResult.Status != "SUCCEEDED" || readResult.Stdout != "download s" || !readResult.StdoutTruncated {
		t.Fatalf("read result=%+v", readResult)
	}

	downloadRequest := agentOperationFixture(t, a, `{"type":"fs.download","payload":{"path":"`+source+`"}}`)
	downloadResult := approveAndExecuteStored(t, a, deviceKey, downloadRequest, OperationExecutionOptions{})
	if downloadResult.Status != "SUCCEEDED" {
		t.Fatalf("download result=%+v", downloadResult)
	}
	artifact, err := a.DownloadArtifact(context.Background(), downloadRequest.Request)
	if err != nil || string(artifact.Data) != "download secret\n" || artifact.Name != "source.txt" {
		t.Fatalf("artifact=%+v err=%v", artifact, err)
	}

	patchRequest := agentOperationFixture(t, a, `{"type":"fs.patch_unified","payload":{"path":"`+patched+`","diff":"--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new\n"}}`)
	patchResult := approveAndExecuteStored(t, a, deviceKey, patchRequest, OperationExecutionOptions{})
	if patchResult.Status != "SUCCEEDED" {
		t.Fatalf("patch result=%+v", patchResult)
	}
	if content, err := os.ReadFile(patched); err != nil || string(content) != "new\n" {
		t.Fatalf("patched=%q err=%v", content, err)
	}

	configRequest := agentOperationFixture(t, a, `{"type":"conf.set","payload":{"path":"`+config+`","format":"env","key":"VALUE","value":"new","create":true}}`)
	configResult := approveAndExecuteStored(t, a, deviceKey, configRequest, OperationExecutionOptions{})
	if configResult.Status != "SUCCEEDED" {
		t.Fatalf("config result=%+v", configResult)
	}
	if content, err := os.ReadFile(config); err != nil || string(content) != "VALUE=new\n" {
		t.Fatalf("config=%q err=%v", content, err)
	}

	uploadData := []byte("uploaded atomically\n")
	upload, _ := stagedUploadFixture(t, a, uploadData)
	uploadRequest := agentOperationFixture(t, a, `{"type":"fs.upload","payload":{"path":"`+target+`","upload_id":"`+upload.UploadID+`","mode":"0600"}}`)
	uploadResult := approveAndExecuteStored(t, a, deviceKey, uploadRequest, OperationExecutionOptions{})
	if uploadResult.Status != "SUCCEEDED" {
		t.Fatalf("upload result=%+v", uploadResult)
	}
	if content, err := os.ReadFile(target); err != nil || string(content) != string(uploadData) {
		t.Fatalf("target=%q err=%v", content, err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("target stat=%v err=%v", info, err)
	}
	if _, err := a.StagedUploadForRequest(context.Background(), uploadRequest.Request, upload.UploadID); err == nil {
		t.Fatal("successful upload retained staged bytes")
	}
}
