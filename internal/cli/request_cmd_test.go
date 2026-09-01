package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCLIRunScriptStagesExactFileAndUsesInterpreterStdin(t *testing.T) {
	script := "set -Eeuo pipefail\nprintf '%s\\n' \"$VALUE\" '{{json .Mounts}}'\n"
	path := t.TempDir() + "/maintenance.sh"
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	var staged []byte
	var payload struct {
		Argv          []string `json:"argv"`
		StdinUploadID string   `json:"stdin_upload_id"`
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/uploads":
			staged, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte(`{"upload_id":"11111111-1111-4111-8111-111111111111","size":64,"sha256":"abc123"}`))
		case "/v1/requests":
			var body struct {
				Op struct {
					Payload json.RawMessage `json:"payload"`
				} `json:"op"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if err := json.Unmarshal(body.Op.Payload, &payload); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			_, _ = w.Write([]byte(`{"request_id":"req-script","status":"PENDING_APPROVAL"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out, errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{
		"run", "--host", ts.URL, "--token", "tok", "--no-wait",
		"--script", path, "--interpreter", "/bin/bash",
	})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if string(staged) != script {
		t.Fatalf("staged=%q want exact script %q", staged, script)
	}
	if strings.Join(payload.Argv, "\x00") != "/bin/bash\x00-s" || payload.StdinUploadID == "" {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestCLIRunScriptStdinReadsInjectedInput(t *testing.T) {
	input := "echo '$VALUE'\n"
	var staged []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/uploads":
			staged, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte(`{"upload_id":"11111111-1111-4111-8111-111111111111","size":14,"sha256":"abc123"}`))
		case "/v1/requests":
			_, _ = w.Write([]byte(`{"request_id":"req-script","status":"PENDING_APPROVAL"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out, errOut bytes.Buffer
	code := NewRootWithInput(strings.NewReader(input), &out, &errOut).Run([]string{
		"run", "--host", ts.URL, "--token", "tok", "--no-wait", "--script-stdin",
	})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if string(staged) != input {
		t.Fatalf("staged=%q want %q", staged, input)
	}
}

func TestCLIRunStdinFilePreservesDirectCommandArgv(t *testing.T) {
	input := "select 1;\n"
	path := t.TempDir() + "/query.sql"
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write SQL: %v", err)
	}
	var argv []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/uploads":
			got, _ := io.ReadAll(r.Body)
			if string(got) != input {
				t.Fatalf("staged=%q", got)
			}
			_, _ = w.Write([]byte(`{"upload_id":"11111111-1111-4111-8111-111111111111","size":10,"sha256":"abc123"}`))
		case "/v1/requests":
			var body struct {
				Op struct {
					Payload struct {
						Argv []string `json:"argv"`
					} `json:"payload"`
				} `json:"op"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			argv = body.Op.Payload.Argv
			_, _ = w.Write([]byte(`{"request_id":"req-sql","status":"PENDING_APPROVAL"}`))
		}
	}))
	defer ts.Close()

	var out, errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{
		"run", "--host", ts.URL, "--token", "tok", "--no-wait",
		"--stdin-file", path, "--", "isql", "-database", "main.fdb",
	})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if strings.Join(argv, "\x00") != "isql\x00-database\x00main.fdb" {
		t.Fatalf("argv=%q", argv)
	}
}

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
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1/logs/live":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
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
	if !strings.Contains(errOut.String(), "status: SUBMITTED") {
		t.Fatalf("stderr=%q, want submitted client state", errOut.String())
	}
	for _, want := range []string{"Request: req1", "Status: SUCCEEDED", "Exit code: 0", "stdout:\nhello\n", "stderr:\nwarn\n"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout=%q, want contains %q", out.String(), want)
		}
	}
}

func TestCLIRunAcceptsExecutionTimeoutAsDuration(t *testing.T) {
	var timeoutSec int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/requests":
			var posted struct {
				Op struct {
					Payload struct {
						TimeoutSec int `json:"timeout_sec"`
					} `json:"payload"`
				} `json:"op"`
			}
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatalf("decode: %v", err)
			}
			timeoutSec = posted.Op.Payload.TimeoutSec
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"PENDING_APPROVAL"}`))
		default:
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{
		"run", "--host", ts.URL, "--token", "tok", "--no-wait",
		"--execution-timeout", "1m30s", "--", "/bin/echo", "hi",
	})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if timeoutSec != 90 {
		t.Fatalf("timeout_sec=%d, want 90", timeoutSec)
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

func TestCLIRequestLogsRedactsByDefaultAndAllowsUnredactedOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("TOKEN=secret-value\n"))
	}))
	defer ts.Close()

	for _, tc := range []struct {
		name      string
		args      []string
		want      string
		doNotWant string
	}{
		{name: "default", want: "TOKEN=[REDACTED]", doNotWant: "secret-value"},
		{name: "unredacted", args: []string{"--unredacted"}, want: "TOKEN=secret-value", doNotWant: "[REDACTED]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			args := []string{"request", "logs", "req1", "--host", ts.URL, "--token", "tok", "--stdout"}
			args = append(args, tc.args...)
			code := NewRoot(&out, &errOut).Run(args)
			if code != 0 {
				t.Fatalf("code=%d stderr=%s", code, errOut.String())
			}
			if !strings.Contains(out.String(), tc.want) || strings.Contains(out.String(), tc.doNotWant) {
				t.Fatalf("stdout=%q want %q without %q", out.String(), tc.want, tc.doNotWant)
			}
		})
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

func TestCLIRequestWaitShowsTransitionsStreamsOutputAndPrintsReport(t *testing.T) {
	statuses := []string{
		`{"request_id":"req1","status":"PENDING_APPROVAL","created_at":"2026-08-26T10:00:00Z"}`,
		`{"request_id":"req1","status":"QUEUED","created_at":"2026-08-26T10:00:00Z","decision":{"decided_at":"2026-08-26T10:02:00Z"}}`,
		`{"request_id":"req1","status":"RUNNING","created_at":"2026-08-26T10:00:00Z","decision":{"decided_at":"2026-08-26T10:02:00Z"}}`,
		`{"request_id":"req1","status":"SUCCEEDED","created_at":"2026-08-26T10:00:00Z","decision":{"decided_at":"2026-08-26T10:02:00Z"},"result":{"started_at":"2026-08-26T10:02:03Z","finished_at":"2026-08-26T10:02:08Z","duration_ms":5000,"exit_code":0,"stdout":"hello\n","stderr":"","stdout_truncated":false,"stderr_truncated":false}}`,
	}
	var statusGets atomic.Int32
	var liveGets atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1":
			i := int(statusGets.Add(1)) - 1
			if i >= len(statuses) {
				i = len(statuses) - 1
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(statuses[i]))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1/logs/live":
			if liveGets.Add(1) < 2 {
				_, _ = w.Write([]byte("O: hel"))
				return
			}
			_, _ = w.Write([]byte("O: hello\n"))
		default:
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{
		"request", "wait", "req1",
		"--host", ts.URL, "--token", "tok",
		"--poll-interval", "1ms", "--status-interval", "0",
	})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}
	for _, want := range []string{"status: PENDING_APPROVAL", "status: QUEUED", "status: RUNNING", "status: SUCCEEDED"} {
		if !strings.Contains(errOut.String(), want) {
			t.Fatalf("stderr=%q, want %q", errOut.String(), want)
		}
	}
	for _, want := range []string{
		"O: hello\n",
		"Request: req1",
		"Status: SUCCEEDED",
		"Approval wait: 2m0s",
		"Queue wait: 3s",
		"Execution: 5s",
		"Exit code: 0",
		"Stdout: 6 B",
		"Output truncated: no",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout=%q, want %q", out.String(), want)
		}
	}
	if strings.Count(out.String(), "hello") != 1 {
		t.Fatalf("live output was duplicated in final result: %q", out.String())
	}
}

func TestCLIRequestWaitReconnectsWithoutCreatingOrCancellingRequest(t *testing.T) {
	var gets atomic.Int32
	var nonGets atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			nonGets.Add(1)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1":
			if gets.Add(1) == 1 {
				http.Error(w, "temporary", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"SUCCEEDED","result":{"exit_code":7,"stdout":"done\n","stderr":""}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1/logs/live":
			_, _ = w.Write([]byte(""))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{
		"request", "wait", "req1",
		"--host", ts.URL, "--token", "tok",
		"--poll-interval", "1ms", "--reconnect-timeout", "100ms", "--status-interval", "0",
	})
	if code != 7 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}
	for _, want := range []string{"status: CONNECTION_LOST", "status: CONNECTION_RESTORED"} {
		if !strings.Contains(errOut.String(), want) {
			t.Fatalf("stderr=%q, want %q", errOut.String(), want)
		}
	}
	if nonGets.Load() != 0 {
		t.Fatalf("wait sent %d non-GET requests", nonGets.Load())
	}
}

func TestCLIRequestWaitTimeoutDoesNotCancelRemoteRequest(t *testing.T) {
	var killCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/kill") {
			killCalls.Add(1)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1" {
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"PENDING_APPROVAL"}`))
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1/logs/live" {
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := NewRoot(&out, &errOut).Run([]string{
		"request", "wait", "req1",
		"--host", ts.URL, "--token", "tok",
		"--poll-interval", "1ms", "--wait-timeout", "10ms", "--status-interval", "1ns",
	})
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if killCalls.Load() != 0 {
		t.Fatalf("local timeout sent %d remote kill requests", killCalls.Load())
	}
	for _, want := range []string{
		"request is still pending approval",
		"The remote request was not cancelled.",
		"racg request wait req1",
	} {
		if !strings.Contains(errOut.String(), want) {
			t.Fatalf("stderr=%q, want %q", errOut.String(), want)
		}
	}
}

func TestCLIRequestWaitTimeoutInterruptsHungStatusPoll(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/requests/req1" {
			http.NotFound(w, r)
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(release)
		ts.Close()
	}()

	var out bytes.Buffer
	var errOut bytes.Buffer
	started := time.Now()
	code := NewRoot(&out, &errOut).Run([]string{
		"request", "wait", "req1",
		"--host", ts.URL, "--token", "tok",
		"--wait-timeout", "30ms", "--reconnect-timeout", "30ms", "--status-interval", "0",
	})
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("local timeout took %s", elapsed)
	}
}

func TestRequestExitCodePreservesFullProcessExitCodeRange(t *testing.T) {
	for _, code := range []int{0, 1, 125, 126, 127, 255} {
		rec := requestStatusResp{Status: "FAILED", Result: &resultStatus{ExitCode: code}}
		if got := requestExitCode(rec); got != code {
			t.Fatalf("exit code %d normalized to %d", code, got)
		}
	}
	for _, code := range []int{-1, 256} {
		rec := requestStatusResp{Status: "FAILED", Result: &resultStatus{ExitCode: code}}
		if got := requestExitCode(rec); got != 1 {
			t.Fatalf("invalid exit code %d normalized to %d", code, got)
		}
	}
}

func TestPrintRequestReportFallsBackToStoredStreams(t *testing.T) {
	rec := requestStatusResp{
		RequestID: "req1",
		Status:    "FAILED",
		Result: &resultStatus{
			ExitCode:        9,
			Stdout:          "partial\n",
			Stderr:          "failed\n",
			StdoutTruncated: true,
		},
	}
	var out bytes.Buffer
	printRequestReport(&out, rec, false)
	for _, want := range []string{"Status: FAILED", "Exit code: 9", "stdout:\npartial\n", "stderr:\nfailed\n", "Output truncated: yes"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("report=%q, want %q", out.String(), want)
		}
	}
}

func TestWaitHeartbeatTextDescribesCurrentState(t *testing.T) {
	for status, want := range map[string]string{
		"PENDING_APPROVAL": "pending approval",
		"APPROVED":         "approved and waiting for execution",
		"QUEUED":           "queued for execution",
		"RUNNING":          "running without new status",
	} {
		if got := waitHeartbeatText(status, time.Minute); !strings.Contains(got, want) {
			t.Fatalf("status=%s heartbeat=%q, want %q", status, got, want)
		}
	}
}
