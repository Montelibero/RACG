package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIFileUploadStreamsContentAndCreatesApprovedRequest(t *testing.T) {
	content := []byte{0x00, 0xff, 'r', 'a', 'c', 'g'}
	sum := sha256.Sum256(content)
	local := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(local, content, 0o600); err != nil {
		t.Fatal(err)
	}
	var posted map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/uploads":
			got, _ := io.ReadAll(r.Body)
			if !bytes.Equal(got, content) || r.Header.Get("Content-Type") != "application/octet-stream" {
				t.Fatalf("uploaded=%x content-type=%q", got, r.Header.Get("Content-Type"))
			}
			fmt.Fprintf(w, `{"upload_id":"up1","size":%d,"sha256":"%s"}`, len(content), hex.EncodeToString(sum[:]))
		case "/v1/requests":
			_ = json.NewDecoder(r.Body).Decode(&posted)
			_, _ = w.Write([]byte(`{"request_id":"req-upload","status":"PENDING_APPROVAL"}`))
		case "/v1/requests/req-upload":
			_, _ = w.Write([]byte(`{"request_id":"req-upload","status":"SUCCEEDED","result":{"exit_code":0,"stdout":"uploaded","stderr":""}}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out, errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{"file", "upload", local, "/srv/data.bin", "--mode", "0640", "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	b, _ := json.Marshal(posted)
	for _, want := range []string{`"type":"fs.upload"`, `"path":"/srv/data.bin"`, `"upload_id":"up1"`, `"mode":"0640"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("request missing %s: %s", want, b)
		}
	}
}

func TestCLIFileDownloadWritesAtomicallyAndChecksHash(t *testing.T) {
	content := []byte{0x00, 0xff, 'd', 'a', 't', 'a'}
	sum := sha256.Sum256(content)
	var posted map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/requests":
			_ = json.NewDecoder(r.Body).Decode(&posted)
			_, _ = w.Write([]byte(`{"request_id":"req-download","status":"PENDING_APPROVAL"}`))
		case "/v1/requests/req-download":
			_, _ = w.Write([]byte(`{"request_id":"req-download","status":"SUCCEEDED","result":{"exit_code":0,"stdout":"ready","stderr":""}}`))
		case "/v1/requests/req-download/file":
			w.Header().Set("X-RACG-SHA256", hex.EncodeToString(sum[:]))
			w.Header().Set("X-RACG-Mode", "0600")
			_, _ = w.Write(content)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	dest := filepath.Join(t.TempDir(), "download.bin")
	var out, errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{"file", "download", "/srv/data.bin", dest, "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("downloaded=%x err=%v", got, err)
	}
	info, _ := os.Stat(dest)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	b, _ := json.Marshal(posted)
	if !bytes.Contains(b, []byte(`"type":"fs.download"`)) || !bytes.Contains(b, []byte(`"path":"/srv/data.bin"`)) {
		t.Fatalf("request=%s", b)
	}
}

func TestDownloadRequestFileDoesNotReplaceDestinationWithoutForce(t *testing.T) {
	content := []byte("new")
	sum := sha256.Sum256(content)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RACG-SHA256", hex.EncodeToString(sum[:]))
		_, _ = w.Write(content)
	}))
	defer ts.Close()
	client, err := newRACGClient(ts.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "existing.bin")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.downloadRequestFile("req", dest, false); err == nil {
		t.Fatal("expected existing destination error")
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "old" {
		t.Fatalf("destination replaced: %q", got)
	}
}

func TestCLIFileReadCreatesFSReadRequestAndWaits(t *testing.T) {
	var posted struct {
		Op struct {
			Type    string `json:"type"`
			Payload struct {
				Path     string `json:"path"`
				MaxBytes int    `json:"max_bytes"`
			} `json:"payload"`
		} `json:"op"`
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization=%q", got)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/requests":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatalf("decode post: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"PENDING_APPROVAL"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"SUCCEEDED","result":{"exit_code":0,"stdout":"global\n    maxconn 2000\n","stderr":""}}`))
		default:
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"file", "read", "/apps/haproxy/haproxy.cfg", "--max-bytes", "4096", "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}

	if posted.Op.Type != "fs.read" {
		t.Fatalf("op.type=%q", posted.Op.Type)
	}
	if posted.Op.Payload.Path != "/apps/haproxy/haproxy.cfg" || posted.Op.Payload.MaxBytes != 4096 {
		t.Fatalf("payload=%+v", posted.Op.Payload)
	}
	for _, want := range []string{"request_id: req1", "status: SUCCEEDED", "stdout:", "1 | global", "2 |     maxconn 2000"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, out.String())
		}
	}
}

func TestCLIFileReadPlainUnredactedPrintsExactStoredContent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/requests":
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"PENDING_APPROVAL"}`))
		case "/v1/requests/req1":
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"SUCCEEDED","result":{"exit_code":0,"stdout":"PASSWORD=hunter2\nline two\n","stderr":""}}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out, errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{"file", "read", "/etc/app.conf", "--plain", "--unredacted", "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "stdout:\nPASSWORD=hunter2\nline two\n") {
		t.Fatalf("stdout was transformed:\n%s", out.String())
	}
}

func TestCLIFilePatchCreatesFSPatchRequestNoWait(t *testing.T) {
	var posted struct {
		Op struct {
			Type    string `json:"type"`
			Payload struct {
				Path string `json:"path"`
				Diff string `json:"diff"`
			} `json:"payload"`
		} `json:"op"`
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization=%q", got)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/requests" {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Fatalf("decode post: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"request_id":"req2","status":"PENDING_APPROVAL"}`))
	}))
	defer ts.Close()

	diff := "@@ -1,2 +1,2 @@\n global\n-    maxconn 2000\n+    maxconn 4000\n"
	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"file", "patch", "/apps/haproxy/haproxy.cfg", "--diff", diff, "--no-wait", "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}

	if posted.Op.Type != "fs.patch_unified" {
		t.Fatalf("op.type=%q", posted.Op.Type)
	}
	if posted.Op.Payload.Path != "/apps/haproxy/haproxy.cfg" || posted.Op.Payload.Diff != diff {
		t.Fatalf("payload=%+v", posted.Op.Payload)
	}
	if !strings.Contains(out.String(), "request_id: req2") || !strings.Contains(out.String(), "status: PENDING_APPROVAL") {
		t.Fatalf("stdout=%s", out.String())
	}
}

func TestCLIFileUsageDocumentsReadAndPatch(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)

	code := root.Run([]string{"file"})
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	got := errOut.String()
	for _, want := range []string{
		"racg file read <path>",
		"racg file patch <path>",
		"racg file upload <local-path> <remote-path>",
		"racg file download <remote-path> <local-path>",
		"--diff-file",
		"fs.read",
		"fs.patch_unified",
		"fs.upload",
		"fs.download",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("usage missing %q:\n%s", want, got)
		}
	}
}
