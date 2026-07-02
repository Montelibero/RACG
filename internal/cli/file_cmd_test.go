package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	for _, want := range []string{"request_id: req1", "status: SUCCEEDED", "stdout:", "maxconn 2000"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, out.String())
		}
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
		"--diff-file",
		"fs.read",
		"fs.patch_unified",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("usage missing %q:\n%s", want, got)
		}
	}
}
