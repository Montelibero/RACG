package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/executor"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

func TestFileUploadAndDownloadTransferBinaryContent(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
	tm := auth.NewTokenManager(auth.RealClock{})
	token, _ := tm.Issue("sess-transfer", "client-transfer", time.Hour)
	api := New(cfg, WithTokenManager(tm))
	handler := api.Handler()

	uploaded := []byte{0x00, 0x01, 0xfe, 0xff, '\n', 'R', 'A', 'C', 'G'}
	sum := sha256.Sum256(uploaded)
	uploadReq := httptest.NewRequest(http.MethodPost, "http://example/v1/uploads", bytes.NewReader(uploaded))
	uploadReq.Header.Set("Authorization", "Bearer "+token)
	uploadReq.Header.Set("Content-Type", "application/octet-stream")
	uploadRW := httptest.NewRecorder()
	handler.ServeHTTP(uploadRW, uploadReq)
	if uploadRW.Code != http.StatusOK {
		t.Fatalf("stage upload status=%d body=%s", uploadRW.Code, uploadRW.Body.String())
	}
	var staged struct {
		UploadID string `json:"upload_id"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal(uploadRW.Body.Bytes(), &staged); err != nil {
		t.Fatalf("decode staged upload: %v", err)
	}
	if staged.UploadID == "" || staged.Size != int64(len(uploaded)) || staged.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("staged=%+v", staged)
	}

	remotePath := filepath.Join(t.TempDir(), "uploaded.bin")
	uploadOp, _ := json.Marshal(map[string]any{
		"op": map[string]any{
			"type": "fs.upload",
			"payload": map[string]any{
				"path": remotePath, "upload_id": staged.UploadID,
				"size": staged.Size, "sha256": staged.SHA256, "mode": "0600",
			},
		},
	})
	uploadCreate := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(uploadOp))
	uploadCreate.Header.Set("Authorization", "Bearer "+token)
	uploadCreateRW := httptest.NewRecorder()
	handler.ServeHTTP(uploadCreateRW, uploadCreate)
	if uploadCreateRW.Code != http.StatusOK {
		t.Fatalf("create upload request status=%d body=%s", uploadCreateRW.Code, uploadCreateRW.Body.String())
	}
	var uploadCreated struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(uploadCreateRW.Body.Bytes(), &uploadCreated)
	if err := api.DecideForTUI(uploadCreated.RequestID, "ALLOW_ONCE"); err != nil {
		t.Fatalf("approve upload: %v", err)
	}
	waitRequestTerminalForTest(t, api, token, uploadCreated.RequestID)
	got, err := os.ReadFile(remotePath)
	if err != nil {
		t.Fatalf("read uploaded file: %v", err)
	}
	if !bytes.Equal(got, uploaded) {
		t.Fatalf("uploaded bytes=%x want=%x", got, uploaded)
	}
	info, _ := os.Stat(remotePath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("uploaded mode=%o", info.Mode().Perm())
	}

	downloadOp, _ := json.Marshal(map[string]any{
		"op": map[string]any{"type": "fs.download", "payload": map[string]any{"path": remotePath}},
	})
	downloadCreate := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(downloadOp))
	downloadCreate.Header.Set("Authorization", "Bearer "+token)
	downloadCreateRW := httptest.NewRecorder()
	handler.ServeHTTP(downloadCreateRW, downloadCreate)
	var downloadCreated struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(downloadCreateRW.Body.Bytes(), &downloadCreated)
	if err := api.DecideForTUI(downloadCreated.RequestID, "ALLOW_ONCE"); err != nil {
		t.Fatalf("approve download: %v", err)
	}
	waitRequestTerminalForTest(t, api, token, downloadCreated.RequestID)

	downloadReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+downloadCreated.RequestID+"/file", nil)
	downloadReq.Header.Set("Authorization", "Bearer "+token)
	downloadRW := httptest.NewRecorder()
	handler.ServeHTTP(downloadRW, downloadReq)
	if downloadRW.Code != http.StatusOK {
		t.Fatalf("download status=%d body=%s", downloadRW.Code, downloadRW.Body.String())
	}
	if !bytes.Equal(downloadRW.Body.Bytes(), uploaded) {
		t.Fatalf("downloaded bytes=%x want=%x", downloadRW.Body.Bytes(), uploaded)
	}
	if downloadRW.Header().Get("X-RACG-SHA256") != staged.SHA256 || downloadRW.Header().Get("X-RACG-Mode") != "0600" {
		t.Fatalf("download headers=%v", downloadRW.Header())
	}
}

func TestCmdRunConsumesStagedStdinAndRemovesIt(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
	tm := auth.NewTokenManager(auth.RealClock{})
	token, _ := tm.Issue("sess-stdin", "client-stdin", time.Hour)
	api := New(cfg, WithTokenManager(tm))
	handler := api.Handler()
	input := []byte("select '$VALUE', '{{json .Mounts}}';\n")

	stage := httptest.NewRequest(http.MethodPost, "http://example/v1/uploads", bytes.NewReader(input))
	stage.Header.Set("Authorization", "Bearer "+token)
	stageRW := httptest.NewRecorder()
	handler.ServeHTTP(stageRW, stage)
	if stageRW.Code != http.StatusOK {
		t.Fatalf("stage status=%d body=%s", stageRW.Code, stageRW.Body.String())
	}
	var staged stagedUpload
	if err := json.Unmarshal(stageRW.Body.Bytes(), &staged); err != nil {
		t.Fatalf("decode staged: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"op": map[string]any{
		"type": "cmd.run", "payload": map[string]any{
			"argv": []string{"/bin/cat"}, "stdin_upload_id": staged.UploadID,
		},
	}})
	create := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(body))
	create.Header.Set("Authorization", "Bearer "+token)
	createRW := httptest.NewRecorder()
	handler.ServeHTTP(createRW, create)
	if createRW.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", createRW.Code, createRW.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRW.Body.Bytes(), &created)
	if err := api.DecideForTUI(created.RequestID, "ALLOW_ONCE"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	rec := waitRequestTerminalForTest(t, api, token, created.RequestID)
	result, _ := rec["result"].(map[string]any)
	if result["stdout"] != string(input) || result["exit_code"] != float64(0) {
		t.Fatalf("result=%+v", result)
	}
	for _, path := range []string{api.uploadDataPath(staged.UploadID), api.uploadMetaPath(staged.UploadID)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("staged file still exists: %s err=%v", path, err)
		}
	}
}

func TestCmdRunRemovesStagedStdinWhenRequestPersistenceFails(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
	tm := auth.NewTokenManager(auth.RealClock{})
	token, _ := tm.Issue("sess-stdin", "client-stdin", time.Hour)
	st, err := store.Open(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	api := New(cfg, WithTokenManager(tm), WithStore(st))
	handler := api.Handler()

	stage := httptest.NewRequest(http.MethodPost, "http://example/v1/uploads", strings.NewReader("echo exact\n"))
	stage.Header.Set("Authorization", "Bearer "+token)
	stageRW := httptest.NewRecorder()
	handler.ServeHTTP(stageRW, stage)
	if stageRW.Code != http.StatusOK {
		t.Fatalf("stage status=%d body=%s", stageRW.Code, stageRW.Body.String())
	}
	var staged stagedUpload
	if err := json.Unmarshal(stageRW.Body.Bytes(), &staged); err != nil {
		t.Fatalf("decode staged: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"op": map[string]any{
		"type": "cmd.run", "payload": map[string]any{
			"argv": []string{"/bin/bash", "-s"}, "stdin_upload_id": staged.UploadID,
		},
	}})
	create := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(body))
	create.Header.Set("Authorization", "Bearer "+token)
	createRW := httptest.NewRecorder()
	handler.ServeHTTP(createRW, create)
	if createRW.Code != http.StatusInternalServerError {
		t.Fatalf("create status=%d body=%s", createRW.Code, createRW.Body.String())
	}
	for _, path := range []string{api.uploadDataPath(staged.UploadID), api.uploadMetaPath(staged.UploadID)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("staged file still exists: %s err=%v", path, err)
		}
	}
}

func TestDeniedCmdRunRemovesStagedStdin(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
	api := New(cfg)
	if err := os.MkdirAll(api.transferDir(), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	id := "11111111-1111-4111-8111-111111111111"
	for path, content := range map[string][]byte{
		api.uploadDataPath(id): []byte("echo no\n"),
		api.uploadMetaPath(id): []byte(`{"upload_id":"11111111-1111-4111-8111-111111111111"}`),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write staged file: %v", err)
		}
	}
	op, _ := json.Marshal(map[string]any{"type": "cmd.run", "payload": map[string]any{
		"argv": []string{"/bin/bash", "-s"}, "stdin_upload_id": id,
	}})
	api.reqs["req-deny-stdin"] = requestRecord{ID: "req-deny-stdin", Status: "PENDING_APPROVAL", Op: op}
	if err := api.DecideForTUI("req-deny-stdin", "DENY"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	for _, path := range []string{api.uploadDataPath(id), api.uploadMetaPath(id)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("staged file still exists: %s err=%v", path, err)
		}
	}
}

func TestCmdRunRejectsStagedStdinFromAnotherSession(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
	api := New(cfg)
	if err := os.MkdirAll(api.transferDir(), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	id := "11111111-1111-4111-8111-111111111111"
	meta, _ := json.Marshal(stagedUpload{UploadID: id, SessionID: "session-a", Size: 1, SHA256: strings.Repeat("a", 64)})
	if err := os.WriteFile(api.uploadMetaPath(id), meta, 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	op := rules.Op{Type: "cmd.run", Payload: json.RawMessage(`{"argv":["/bin/cat"],"stdin_upload_id":"` + id + `"}`)}
	if err := api.prepareTransferOp(auth.Claims{SessionID: "session-b"}, &op); err == nil || !strings.Contains(err.Error(), "another session") {
		t.Fatalf("error=%v", err)
	}
}

func TestCmdRunRejectsClientSuppliedStdinMetadataWithoutUpload(t *testing.T) {
	api := New(config.Defaults())
	op := rules.Op{Type: "cmd.run", Payload: json.RawMessage(`{
		"argv":["/bin/bash","-s"],
		"stdin_size":42,
		"stdin_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}`)}
	if err := api.prepareTransferOp(auth.Claims{SessionID: "session"}, &op); err == nil || !strings.Contains(err.Error(), "stdin_upload_id") {
		t.Fatalf("error=%v", err)
	}
}

func TestStagedStdinCanBeClaimedByOnlyOneRequest(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
	api := New(cfg)
	if err := os.MkdirAll(api.transferDir(), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	id := "11111111-1111-4111-8111-111111111111"
	meta, _ := json.Marshal(stagedUpload{UploadID: id, SessionID: "session", Size: 1, SHA256: strings.Repeat("a", 64)})
	if err := os.WriteFile(api.uploadMetaPath(id), meta, 0o600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	newOp := func() rules.Op {
		return rules.Op{Type: "cmd.run", Payload: json.RawMessage(`{"argv":["/bin/cat"],"stdin_upload_id":"` + id + `"}`)}
	}
	first := newOp()
	if err := api.prepareTransferOp(auth.Claims{SessionID: "session"}, &first); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	second := newOp()
	if err := api.prepareTransferOp(auth.Claims{SessionID: "session"}, &second); err == nil || !strings.Contains(err.Error(), "already claimed") {
		t.Fatalf("second claim error=%v", err)
	}
}

func TestRejectedUploadRemovesStagedContent(t *testing.T) {
	for _, action := range []string{"DENY", "CANCEL"} {
		t.Run(action, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.DBPath = filepath.Join(t.TempDir(), "racg.db")
			api := New(cfg)
			if err := os.MkdirAll(api.transferDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			uploadID := "11111111-1111-4111-8111-111111111111"
			if err := os.WriteFile(api.uploadDataPath(uploadID), []byte("staged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(api.uploadMetaPath(uploadID), []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
			op, _ := json.Marshal(map[string]any{"type": "fs.upload", "payload": map[string]any{"path": "/tmp/file", "upload_id": uploadID}})
			api.reqs["req"] = requestRecord{ID: "req", Status: "PENDING_APPROVAL", Op: op, SessionID: "sess", ClientID: "client"}
			var err error
			if action == "DENY" {
				err = api.DecideForTUI("req", "DENY")
			} else {
				err = api.KillForTUI("req")
			}
			if err != nil {
				t.Fatalf("reject upload: %v", err)
			}
			for _, path := range []string{api.uploadDataPath(uploadID), api.uploadMetaPath(uploadID)} {
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Fatalf("staged path still exists: %s err=%v", path, statErr)
				}
			}
		})
	}
}

func TestInfo(t *testing.T) {
	api := New(config.Defaults())
	req := httptest.NewRequest(http.MethodGet, "http://example/v1/info", nil)
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d", rw.Code)
	}

	var got map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got["server_version"] == "" {
		t.Fatalf("missing server_version")
	}
}

func TestSessionOpenAndMe(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	body := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}

	var resp struct {
		SessionID    string `json:"session_id"`
		SessionToken string `json:"session_token"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.SessionToken == "" {
		t.Fatalf("empty token")
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://example/v1/session/me", nil)
	req2.Header.Set("Authorization", "Bearer "+resp.SessionToken)
	rw2 := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw2, req2)
	if rw2.Code != 200 {
		t.Fatalf("me status=%d body=%s", rw2.Code, rw2.Body.String())
	}
}

func TestSessionOpenPersistsSessionInSQLite(t *testing.T) {
	cfg := config.Defaults()

	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithStore(st))

	body := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}

	var resp struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.SessionID == "" {
		t.Fatalf("empty session_id")
	}

	if _, err := st.GetSession(context.Background(), resp.SessionID); err != nil {
		t.Fatalf("GetSession: %v", err)
	}
}

func TestRequestsCreateRequiresAuth(t *testing.T) {
	api := New(config.Defaults())

	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader([]byte(`{"op":{"type":"cmd.run","payload":{}}}`)))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 401 {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestRequestsCreate(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got["request_id"] == "" {
		t.Fatalf("missing request_id")
	}
	if got["status"] != "PENDING_APPROVAL" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestRequestsCreatePersistsRequestInSQLite(t *testing.T) {
	ctx := context.Background()

	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithStore(st))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionID    string `json:"session_id"`
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var createResp struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	_ = json.Unmarshal(rw.Body.Bytes(), &createResp)
	if createResp.RequestID == "" {
		t.Fatalf("missing request_id")
	}

	got, err := st.GetRequest(ctx, createResp.RequestID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if got.SessionID != openResp.SessionID {
		t.Fatalf("SessionID=%q", got.SessionID)
	}
	if got.Status != createResp.Status {
		t.Fatalf("Status=%q", got.Status)
	}
}

func TestRequestsCreateAutoApproveByRule(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	re := rules.NewEngine()
	re.AddAlways(rules.Rule{ID: "allow-echo", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithRulesEngine(re))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got["status"] != "APPROVED" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestAutoApproveByRulePersistsDecisionInSQLite(t *testing.T) {
	ctx := context.Background()

	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	re := rules.NewEngine()
	re.AddAlways(rules.Rule{ID: "allow-echo", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithRulesEngine(re), WithStore(st), WithExecutor(immediateRunner{}))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	_ = json.Unmarshal(rw.Body.Bytes(), &created)
	if created.RequestID == "" {
		t.Fatalf("missing request_id")
	}
	if created.Status != "APPROVED" {
		t.Fatalf("create status=%q", created.Status)
	}

	gotDec, err := st.GetDecision(ctx, created.RequestID)
	if err != nil {
		t.Fatalf("GetDecision: %v", err)
	}
	if gotDec.DecisionSource != "rule" {
		t.Fatalf("DecisionSource=%q", gotDec.DecisionSource)
	}
	if gotDec.RuleID != "allow-echo" {
		t.Fatalf("RuleID=%q", gotDec.RuleID)
	}
}

func TestRequestsGetByID(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	reqBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("create status=%d body=%s", rw.Code, rw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(rw.Body.Bytes(), &created)

	getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID, nil)
	getReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	getRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(getRw, getReq)
	if getRw.Code != 200 {
		t.Fatalf("get status=%d body=%s", getRw.Code, getRw.Body.String())
	}
}

func TestDecisionDeny(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	decBody := []byte(`{"decision":"DENY"}`)
	decReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/decision", bytes.NewReader(decBody))
	decReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	decReq.Header.Set("Content-Type", "application/json")
	decRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(decRw, decReq)
	if decRw.Code != 200 {
		t.Fatalf("dec status=%d body=%s", decRw.Code, decRw.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID, nil)
	getReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	getRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(getRw, getReq)
	if getRw.Code != 200 {
		t.Fatalf("get status=%d body=%s", getRw.Code, getRw.Body.String())
	}
	var rec map[string]any
	_ = json.Unmarshal(getRw.Body.Bytes(), &rec)
	if rec["status"] != "DENIED" {
		t.Fatalf("status=%v", rec["status"])
	}
}

func TestDecisionPersistsDecisionInSQLite(t *testing.T) {
	ctx := context.Background()

	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithStore(st))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	decBody := []byte(`{"decision":"ALLOW_ONCE"}`)
	decReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/decision", bytes.NewReader(decBody))
	decReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	decReq.Header.Set("Content-Type", "application/json")
	decRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(decRw, decReq)
	if decRw.Code != 200 {
		t.Fatalf("dec status=%d body=%s", decRw.Code, decRw.Body.String())
	}

	gotDec, err := st.GetDecision(ctx, created.RequestID)
	if err != nil {
		t.Fatalf("GetDecision: %v", err)
	}
	if gotDec.Decision != "ALLOW_ONCE" {
		t.Fatalf("decision=%q", gotDec.Decision)
	}

	gotReq, err := st.GetRequest(ctx, created.RequestID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if gotReq.Status != "APPROVED" && gotReq.Status != "QUEUED" && gotReq.Status != "RUNNING" && gotReq.Status != "SUCCEEDED" && gotReq.Status != "FAILED" && gotReq.Status != "TIMED_OUT" && gotReq.Status != "KILLED" {
		t.Fatalf("request status=%q", gotReq.Status)
	}
}

type immediateRunner struct{}

func (im immediateRunner) Run(ctx context.Context, s executor.Spec) executor.Result {
	return executor.Result{
		Status:       "SUCCEEDED",
		ExitCode:     0,
		DurationMs:   1,
		Stdout:       "hi\n",
		Stderr:       "",
		StdoutSHA256: "x",
		StderrSHA256: "y",
	}
}

func TestApprovedRequestReportsQueuedWhileWaitingForExecutionSlot(t *testing.T) {
	cfg := config.Defaults()
	cfg.MaxConcurrency = 1
	api := New(cfg, WithExecutor(immediateRunner{}))
	api.sem <- struct{}{}

	payload, err := json.Marshal(map[string]any{"argv": []string{"/bin/echo", "hi"}})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	api.reqs["req-queued"] = requestRecord{ID: "req-queued", Status: "APPROVED"}
	done := make(chan struct{})
	go func() {
		api.executeApprovedRequest("req-queued", auth.Claims{}, rules.Op{Type: "cmd.run", Payload: payload})
		close(done)
	}()
	defer func() {
		<-api.sem
		<-done
	}()

	deadline := time.Now().Add(time.Second)
	for {
		api.reqsMu.Lock()
		status := api.reqs["req-queued"].Status
		api.reqsMu.Unlock()
		if status == "QUEUED" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status=%q, want QUEUED", status)
		}
		time.Sleep(time.Millisecond)
	}

	if err := api.killInternal(context.Background(), "req-queued", auth.Claims{}); err != nil {
		t.Fatalf("kill queued request: %v", err)
	}
}

func TestExecutionPersistsExecutionInSQLite(t *testing.T) {
	ctx := context.Background()

	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	re := rules.NewEngine()
	re.AddAlways(rules.Rule{ID: "allow-echo", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}}})

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithStore(st), WithRulesEngine(re), WithExecutor(immediateRunner{}))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)
	if created.Status != "APPROVED" {
		t.Fatalf("create status=%q", created.Status)
	}

	// Wait briefly for the async execution to finish and be persisted.
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("execution not persisted in time")
		}
		if _, err := st.GetExecution(ctx, created.RequestID); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	ex, err := st.GetExecution(ctx, created.RequestID)
	if err != nil {
		t.Fatalf("GetExecution: %v", err)
	}
	if ex.Status != "SUCCEEDED" {
		t.Fatalf("exec status=%q", ex.Status)
	}

	reqRow, err := st.GetRequest(ctx, created.RequestID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if reqRow.Status != "SUCCEEDED" {
		t.Fatalf("request status=%q", reqRow.Status)
	}
}

type fakeRunner struct {
	started chan struct{}
	done    chan struct{}
}

func (f *fakeRunner) Run(ctx context.Context, s executor.Spec) executor.Result {
	close(f.started)
	<-ctx.Done()
	close(f.done)
	return executor.Result{Status: "KILLED", ExitCode: -1}
}

func TestKillRunningRequest(t *testing.T) {
	cfg := config.Defaults()
	cfg.DefaultTimeoutSec = 10

	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	fr := &fakeRunner{started: make(chan struct{}), done: make(chan struct{})}

	re := rules.NewEngine()
	re.AddAlways(rules.Rule{ID: "allow-sleep", OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: []string{"/bin/sleep"}}})

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithRulesEngine(re), WithExecutor(fr))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/sleep","2"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	<-fr.started

	killReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/kill", nil)
	killReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	killRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(killRw, killReq)
	if killRw.Code != 200 {
		t.Fatalf("kill status=%d body=%s", killRw.Code, killRw.Body.String())
	}
	<-fr.done
}

func TestKillPendingRequestCancelsIt(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/echo","hi"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	killReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/kill", nil)
	killReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	killRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(killRw, killReq)
	if killRw.Code != 200 {
		t.Fatalf("kill status=%d body=%s", killRw.Code, killRw.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID, nil)
	getReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	getRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(getRw, getReq)
	if getRw.Code != 200 {
		t.Fatalf("get status=%d body=%s", getRw.Code, getRw.Body.String())
	}
	var rec map[string]any
	_ = json.Unmarshal(getRw.Body.Bytes(), &rec)
	if rec["status"] != "CANCELED" {
		t.Fatalf("status=%v body=%s", rec["status"], getRw.Body.String())
	}
}

func TestFSReadExecution(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	dir := t.TempDir()
	p := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(p, []byte("hello\nworld\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"fs.read","payload":{"path":"` + p + `"}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	decBody := []byte(`{"decision":"ALLOW_ONCE"}`)
	decReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/decision", bytes.NewReader(decBody))
	decReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	decReq.Header.Set("Content-Type", "application/json")
	decRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(decRw, decReq)
	if decRw.Code != 200 {
		t.Fatalf("dec status=%d body=%s", decRw.Code, decRw.Body.String())
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("request did not finish in time")
		}
		getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID, nil)
		getReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
		getRw := httptest.NewRecorder()
		api.Handler().ServeHTTP(getRw, getReq)
		if getRw.Code != 200 {
			t.Fatalf("get status=%d body=%s", getRw.Code, getRw.Body.String())
		}

		var rec map[string]any
		_ = json.Unmarshal(getRw.Body.Bytes(), &rec)
		if rec["status"] == "RUNNING" || rec["status"] == "QUEUED" || rec["status"] == "APPROVED" || rec["status"] == "PENDING_APPROVAL" {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if rec["status"] != "SUCCEEDED" {
			t.Fatalf("status=%v body=%s", rec["status"], getRw.Body.String())
		}
		res := rec["result"].(map[string]any)
		if res["stdout"] != "hello\nworld\n" {
			t.Fatalf("stdout=%q", res["stdout"])
		}
		return
	}
}

func TestRequestLogsEndpointsReturnRawStreams(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"cmd.run","payload":{"argv":["/bin/sh","-c","echo out; echo err >&2"]}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	decideBody := []byte(`{"decision":"ALLOW_ONCE"}`)
	decideReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/decision", bytes.NewReader(decideBody))
	decideReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	decideReq.Header.Set("Content-Type", "application/json")
	decideRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(decideRw, decideReq)
	if decideRw.Code != 200 {
		t.Fatalf("decision status=%d body=%s", decideRw.Code, decideRw.Body.String())
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("request did not finish in time")
		}
		getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID, nil)
		getReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
		getRw := httptest.NewRecorder()
		api.Handler().ServeHTTP(getRw, getReq)
		var rec map[string]any
		_ = json.Unmarshal(getRw.Body.Bytes(), &rec)
		if rec["status"] == "SUCCEEDED" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	stdoutReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID+"/logs/stdout", nil)
	stdoutReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	stdoutRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(stdoutRw, stdoutReq)
	if stdoutRw.Code != 200 {
		t.Fatalf("stdout status=%d body=%s", stdoutRw.Code, stdoutRw.Body.String())
	}
	if got := stdoutRw.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("stdout content-type=%q", got)
	}
	if stdoutRw.Body.String() != "out\n" {
		t.Fatalf("stdout=%q", stdoutRw.Body.String())
	}

	stderrReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID+"/logs/stderr", nil)
	stderrReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	stderrRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(stderrRw, stderrReq)
	if stderrRw.Code != 200 {
		t.Fatalf("stderr status=%d body=%s", stderrRw.Code, stderrRw.Body.String())
	}
	if stderrRw.Body.String() != "err\n" {
		t.Fatalf("stderr=%q", stderrRw.Body.String())
	}
}

func TestLiveLogEndpointReturnsRunningOutput(t *testing.T) {
	api := New(config.Defaults())
	token, _ := api.tokens.Issue("sess1", "client1", time.Hour)

	api.reqsMu.Lock()
	api.reqs["req-live"] = requestRecord{ID: "req-live", Status: "RUNNING", SessionID: "sess1", ClientID: "client1"}
	api.reqsMu.Unlock()
	api.liveMu.Lock()
	api.live["req-live"] = &liveOutput{combined: []byte("O: first\nE: warn\n"), maxBytes: 1024, requestID: "req-live"}
	api.liveMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/req-live/logs/live", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rw := httptest.NewRecorder()
	api.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status=%d body=%s", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("content-type=%q", got)
	}
	if rw.Body.String() != "O: first\nE: warn\n" {
		t.Fatalf("body=%q", rw.Body.String())
	}
}

func TestFSPatchUnifiedExecution(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	dir := t.TempDir()
	p := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(p, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	patch := `@@ -1,3 +1,3 @@
 a
-b
+B
 c
`

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	createBody := []byte(`{"op":{"type":"fs.patch_unified","payload":{"path":"` + p + `","diff":` + mustJSONString(t, patch) + `}}}`)
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	decBody := []byte(`{"decision":"ALLOW_ONCE"}`)
	decReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/decision", bytes.NewReader(decBody))
	decReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	decReq.Header.Set("Content-Type", "application/json")
	decRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(decRw, decReq)
	if decRw.Code != 200 {
		t.Fatalf("dec status=%d body=%s", decRw.Code, decRw.Body.String())
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("request did not finish in time")
		}
		getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+created.RequestID, nil)
		getReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
		getRw := httptest.NewRecorder()
		api.Handler().ServeHTTP(getRw, getReq)
		if getRw.Code != 200 {
			t.Fatalf("get status=%d body=%s", getRw.Code, getRw.Body.String())
		}
		var rec map[string]any
		_ = json.Unmarshal(getRw.Body.Bytes(), &rec)
		if rec["status"] == "RUNNING" || rec["status"] == "QUEUED" || rec["status"] == "APPROVED" || rec["status"] == "PENDING_APPROVAL" {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if rec["status"] != "SUCCEEDED" {
			t.Fatalf("status=%v body=%s", rec["status"], getRw.Body.String())
		}
		break
	}

	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "a\nB\nc\n" {
		t.Fatalf("file=%q", string(got))
	}
}

func TestApplyUnifiedPatchTextInsertsIntoEmptyFile(t *testing.T) {
	patch := `--- a/haproxy.cfg
+++ b/haproxy.cfg
@@ -0,0 +1,2 @@
+global
+    maxconn 2000
`
	got, err := applyUnifiedPatchText("", patch)
	if err != nil {
		t.Fatalf("applyUnifiedPatchText: %v", err)
	}
	if want := "global\n    maxconn 2000\n"; got != want {
		t.Fatalf("result=%q, want %q", got, want)
	}
}

func TestApplyUnifiedPatchTextHonorsNoNewlineMarker(t *testing.T) {
	patch := "@@ -0,0 +1 @@\n+global\n\\ No newline at end of file\n"
	got, err := applyUnifiedPatchText("", patch)
	if err != nil {
		t.Fatalf("applyUnifiedPatchText: %v", err)
	}
	if got != "global" {
		t.Fatalf("result=%q, want no trailing newline", got)
	}
}

func TestConfSetExecutionUpdatesConfigWithBackup(t *testing.T) {
	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	dir := t.TempDir()
	p := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(p, []byte("image:\n  repository: app\n  tag: old\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	api := New(cfg, WithPairing(pair), WithTokenManager(tm))

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	body := map[string]any{
		"op": map[string]any{
			"type": "conf.set",
			"payload": map[string]any{
				"path":       p,
				"format":     "yaml",
				"key":        "image.tag",
				"value":      "v1.2.3",
				"value_type": "string",
				"backup":     true,
			},
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	createReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(bodyBytes))
	createReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq.Header.Set("Content-Type", "application/json")
	createRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw, createReq)
	if createRw.Code != 200 {
		t.Fatalf("create status=%d body=%s", createRw.Code, createRw.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw.Body.Bytes(), &created)

	decReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created.RequestID+"/decision", bytes.NewReader([]byte(`{"decision":"ALLOW_ONCE"}`)))
	decReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	decReq.Header.Set("Content-Type", "application/json")
	decRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(decRw, decReq)
	if decRw.Code != 200 {
		t.Fatalf("dec status=%d body=%s", decRw.Code, decRw.Body.String())
	}

	rec := waitRequestTerminalForTest(t, api, openResp.SessionToken, created.RequestID)
	if rec["status"] != "SUCCEEDED" {
		t.Fatalf("status=%v body=%v", rec["status"], rec)
	}
	result := rec["result"].(map[string]any)
	stdout := result["stdout"].(string)
	for _, want := range []string{"path: " + p, "key: image.tag", "old: old", "new: v1.2.3", "backup_path:"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "tag: v1.2.3") {
		t.Fatalf("file=%q", string(got))
	}
}

func TestConfSetExecutionCreatesMissingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.yaml")
	payload, err := json.Marshal(map[string]any{
		"path":       path,
		"format":     "yaml",
		"key":        "network.version",
		"value":      "2",
		"value_type": "int",
		"create":     true,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	op := rules.Op{Type: "conf.set", Payload: payload}
	api := New(config.Defaults())
	api.reqs["req-create"] = requestRecord{ID: "req-create", Status: "APPROVED"}

	api.executeApprovedRequest("req-create", auth.Claims{}, op)

	rec := api.reqs["req-create"]
	if rec.Status != "SUCCEEDED" || rec.Result == nil {
		t.Fatalf("request=%+v", rec)
	}
	for _, want := range []string{"file_created: true", "created: true"} {
		if !strings.Contains(rec.Result.Stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, rec.Result.Stdout)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%#o, want 0600", got)
	}
}

func TestAllowAlwaysCreatesPatchRuleAndAutoApprovesNext(t *testing.T) {
	ctx := context.Background()

	cfg := config.Defaults()
	clk := auth.NewFakeClock(time.Unix(1000, 0).UTC())
	pair := auth.NewPairing(6, 3*time.Minute, clk)
	tm := auth.NewTokenManager(clk)

	st, err := store.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	api := New(cfg, WithPairing(pair), WithTokenManager(tm), WithStore(st))

	dir := t.TempDir()
	p := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(p, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	patch1 := `@@ -1,3 +1,3 @@
 a
-b
+B
 c
`

	open := []byte(`{"client_id":"codex-home","pairing_code":"` + pair.Code() + `"}`)
	rwOpen := httptest.NewRecorder()
	api.Handler().ServeHTTP(rwOpen, httptest.NewRequest(http.MethodPost, "http://example/v1/session/open", bytes.NewReader(open)))
	if rwOpen.Code != 200 {
		t.Fatalf("open status=%d body=%s", rwOpen.Code, rwOpen.Body.String())
	}
	var openResp struct {
		SessionToken string `json:"session_token"`
	}
	_ = json.Unmarshal(rwOpen.Body.Bytes(), &openResp)

	// Request #1: allow always via TUI decision, should create an always rule for this path.
	createBody1 := []byte(`{"op":{"type":"fs.patch_unified","payload":{"path":"` + p + `","diff":` + mustJSONString(t, patch1) + `}}}`)
	createReq1 := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody1))
	createReq1.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq1.Header.Set("Content-Type", "application/json")
	createRw1 := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw1, createReq1)
	if createRw1.Code != 200 {
		t.Fatalf("create1 status=%d body=%s", createRw1.Code, createRw1.Body.String())
	}
	var created1 struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(createRw1.Body.Bytes(), &created1)

	decBody := []byte(`{"decision":"ALLOW_ALWAYS"}`)
	decReq := httptest.NewRequest(http.MethodPost, "http://example/v1/requests/"+created1.RequestID+"/decision", bytes.NewReader(decBody))
	decReq.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	decReq.Header.Set("Content-Type", "application/json")
	decRw := httptest.NewRecorder()
	api.Handler().ServeHTTP(decRw, decReq)
	if decRw.Code != 200 {
		t.Fatalf("dec status=%d body=%s", decRw.Code, decRw.Body.String())
	}
	waitRequestTerminalForTest(t, api, openResp.SessionToken, created1.RequestID)

	always, err := st.LoadEnabledAlwaysRules(ctx)
	if err != nil {
		t.Fatalf("LoadEnabledAlwaysRules: %v", err)
	}
	if len(always) != 1 {
		t.Fatalf("always len=%d", len(always))
	}
	if always[0].OpType != "fs.patch_unified" {
		t.Fatalf("op_type=%q", always[0].OpType)
	}
	if always[0].Path == nil || always[0].Path.Exact != p {
		t.Fatalf("path=%v", always[0].Path)
	}
	ruleID := always[0].ID

	// Request #2: should auto-approve due to the persisted always rule.
	patch2 := `@@ -1,3 +1,3 @@
 a
-B
+b
 c
`
	createBody2 := []byte(`{"op":{"type":"fs.patch_unified","payload":{"path":"` + p + `","diff":` + mustJSONString(t, patch2) + `}}}`)
	createReq2 := httptest.NewRequest(http.MethodPost, "http://example/v1/requests", bytes.NewReader(createBody2))
	createReq2.Header.Set("Authorization", "Bearer "+openResp.SessionToken)
	createReq2.Header.Set("Content-Type", "application/json")
	createRw2 := httptest.NewRecorder()
	api.Handler().ServeHTTP(createRw2, createReq2)
	if createRw2.Code != 200 {
		t.Fatalf("create2 status=%d body=%s", createRw2.Code, createRw2.Body.String())
	}
	var created2 struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	_ = json.Unmarshal(createRw2.Body.Bytes(), &created2)
	if created2.Status != "APPROVED" {
		t.Fatalf("create2 status=%q body=%s", created2.Status, createRw2.Body.String())
	}

	gotDec, err := st.GetDecision(ctx, created2.RequestID)
	if err != nil {
		t.Fatalf("GetDecision2: %v", err)
	}
	if gotDec.DecisionSource != "rule" {
		t.Fatalf("DecisionSource=%q", gotDec.DecisionSource)
	}
	if gotDec.RuleID != ruleID {
		t.Fatalf("RuleID=%q want=%q", gotDec.RuleID, ruleID)
	}
	waitRequestTerminalForTest(t, api, openResp.SessionToken, created2.RequestID)
}

func waitRequestTerminalForTest(t *testing.T, api *API, token string, requestID string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("request %s did not finish in time", requestID)
		}
		getReq := httptest.NewRequest(http.MethodGet, "http://example/v1/requests/"+requestID, nil)
		getReq.Header.Set("Authorization", "Bearer "+token)
		getRw := httptest.NewRecorder()
		api.Handler().ServeHTTP(getRw, getReq)
		if getRw.Code != 200 {
			t.Fatalf("get status=%d body=%s", getRw.Code, getRw.Body.String())
		}
		var rec map[string]any
		_ = json.Unmarshal(getRw.Body.Bytes(), &rec)
		switch rec["status"] {
		case "RUNNING", "QUEUED", "APPROVED", "PENDING_APPROVAL":
			time.Sleep(10 * time.Millisecond)
			continue
		default:
			return rec
		}
	}
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return string(b)
}
