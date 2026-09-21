package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLIRequestListFetchesSessionScopedHistory(t *testing.T) {
	var gotQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/requests" {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok" {
			t.Fatalf("Authorization=%q", auth)
		}
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"requests":[` +
			`{"request_id":"req2","status":"SUCCEEDED","op":{"type":"cmd.run","payload":{"argv":["/bin/echo","two"]}},"created_at":"2026-09-21T10:01:00Z"},` +
			`{"request_id":"req1","status":"FAILED","op":{"type":"fs.read","payload":{"path":"/var/log/app.log"}},"created_at":"2026-09-21T10:00:00Z"}]}`))
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"request", "list", "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}

	if gotQuery != "scope=session&limit=10" {
		t.Fatalf("query=%q", gotQuery)
	}
	for _, want := range []string{
		"request_id=req2 status=SUCCEEDED op=cmd.run /bin/echo two created_at=2026-09-21T10:01:00Z",
		"request_id=req1 status=FAILED op=fs.read /var/log/app.log created_at=2026-09-21T10:00:00Z",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, out.String())
		}
	}
}

func TestCLIRequestListPassesStatusAndLimit(t *testing.T) {
	var gotQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"requests":[]}`))
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"request", "list", "--status", "FAILED", "--limit", "3", "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if gotQuery != "scope=session&limit=3&status=FAILED" {
		t.Fatalf("query=%q", gotQuery)
	}
	if !strings.Contains(out.String(), "requests: none") {
		t.Fatalf("stdout=%q", out.String())
	}
}

func TestCLIRequestListRejectsInvalidLimit(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	if code := root.Run([]string{"request", "list", "--limit", "0"}); code != 2 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "--limit must be between 1 and 100") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

func TestCLIRequestUsageDocumentsList(t *testing.T) {
	got := requestUsage()
	if !strings.Contains(got, "list") {
		t.Fatalf("usage missing list: %s", got)
	}
	if !strings.Contains(got, "wait") || !strings.Contains(got, "cancel") || !strings.Contains(got, "logs") || !strings.Contains(got, "tail") {
		t.Fatalf("usage lost existing subcommands: %s", got)
	}
}
