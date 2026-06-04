package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLIRunCreatesRequestWaitsAndPrintsSections(t *testing.T) {
	var posted struct {
		Op struct {
			Type    string `json:"type"`
			Payload struct {
				Argv []string `json:"argv"`
			} `json:"payload"`
		} `json:"op"`
	}
	gets := 0

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
			gets++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"SUCCEEDED","result":{"exit_code":0,"stdout":"hello\n","stderr":"warn\n"}}`))
		default:
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"run", "--host", ts.URL, "--token", "tok", "--poll-interval", "1ms", "--", "/bin/echo", "hello"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}

	if posted.Op.Type != "cmd.run" {
		t.Fatalf("op.type=%q", posted.Op.Type)
	}
	if strings.Join(posted.Op.Payload.Argv, " ") != "/bin/echo hello" {
		t.Fatalf("argv=%q", posted.Op.Payload.Argv)
	}
	if gets == 0 {
		t.Fatalf("request was not polled")
	}
	for _, want := range []string{"request_id: req1", "status: SUCCEEDED", "exit_code: 0", "stdout:\nhello\n", "stderr:\nwarn\n"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout=%q, want contains %q", out.String(), want)
		}
	}
}

func TestCLIRequestCancelPostsKillEndpoint(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/requests/req1/kill" {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization=%q", got)
		}
		called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"request", "cancel", "req1", "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !called {
		t.Fatalf("server was not called")
	}
	if !strings.Contains(out.String(), "request_id: req1\nstatus: cancel_requested\n") {
		t.Fatalf("stdout=%q", out.String())
	}
}

func TestCLIRequestLogsPrintsSelectedStreams(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/requests/req1/logs/stdout" {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("out\n"))
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"request", "logs", "req1", "--host", ts.URL, "--token", "tok", "--stdout"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if out.String() != "out\n" {
		t.Fatalf("stdout=%q", out.String())
	}
}

func TestCLIRequestLogsLivePrintsLiveSnapshot(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/requests/req1/logs/live" {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("O: live\n"))
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"request", "logs", "req1", "--host", ts.URL, "--token", "tok", "--live"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if out.String() != "O: live\n" {
		t.Fatalf("stdout=%q", out.String())
	}
}

func TestCLIRequestTailPrintsLiveDeltaUntilTerminal(t *testing.T) {
	liveGets := 0
	statusGets := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1/logs/live":
			liveGets++
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if liveGets == 1 {
				_, _ = w.Write([]byte("abc"))
				return
			}
			_, _ = w.Write([]byte("abcdef"))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1":
			statusGets++
			w.Header().Set("Content-Type", "application/json")
			if statusGets < 2 {
				_, _ = w.Write([]byte(`{"request_id":"req1","status":"RUNNING"}`))
				return
			}
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"SUCCEEDED","result":{"exit_code":0}}`))
		default:
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"request", "tail", "req1", "--host", ts.URL, "--token", "tok", "--poll-interval", "1ms"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if out.String() != "abcdef" {
		t.Fatalf("stdout=%q", out.String())
	}
}
