package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type RequestCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewRequestCmd(stdout, stderr io.Writer) *RequestCmd {
	return &RequestCmd{stdout: stdout, stderr: stderr}
}

func (c *RequestCmd) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, requestUsage())
		return 2
	}

	switch args[0] {
	case "wait":
		return c.runWait(args[1:])
	case "cancel":
		return c.runCancel(args[1:])
	case "logs":
		return c.runLogs(args[1:])
	case "tail":
		return c.runTail(args[1:])
	default:
		fmt.Fprintln(c.stderr, requestUsage())
		return 2
	}
}

func requestUsage() string {
	return "usage: racg request <wait|cancel|logs|tail> [args]"
}

func (c *RequestCmd) RunRun(args []string) int {
	fs := flag.NewFlagSet("racg run", flag.ContinueOnError)
	fs.SetOutput(c.stderr)

	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	cwd := fs.String("cwd", "", "command working directory")
	timeoutSec := fs.Int("timeout", 0, "command timeout in seconds (legacy alias)")
	executionTimeout := fs.Duration("execution-timeout", 0, "maximum remote process execution time")
	noWait := fs.Bool("no-wait", false, "create request and print request id without waiting")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")
	statusInterval := fs.Duration("status-interval", 30*time.Second, "heartbeat interval while status is unchanged; 0 disables")
	reconnectTimeout := fs.Duration("reconnect-timeout", 5*time.Minute, "maximum time to restore observation after a connection failure")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *timeoutSec > 0 && *executionTimeout > 0 {
		fmt.Fprintln(c.stderr, "use either --execution-timeout or --timeout, not both")
		return 2
	}
	if *executionTimeout < 0 {
		fmt.Fprintln(c.stderr, "--execution-timeout must not be negative")
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg run --host URL --token TOKEN -- <command> [args...]")
		return 2
	}

	resolvedHost, resolvedToken, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}

	payload := map[string]any{"argv": argv}
	if *cwd != "" {
		payload["cwd"] = *cwd
	}
	effectiveTimeoutSec := *timeoutSec
	if *executionTimeout > 0 {
		effectiveTimeoutSec = int((*executionTimeout + time.Second - 1) / time.Second)
	}
	if effectiveTimeoutSec > 0 {
		payload["timeout_sec"] = effectiveTimeoutSec
	}
	created, err := client.createRequest(map[string]any{
		"op": map[string]any{
			"type":    "cmd.run",
			"payload": payload,
		},
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "request create failed: %v\n", err)
		return 1
	}

	if *noWait {
		fmt.Fprintf(c.stdout, "request_id: %s\nstatus: %s\n", created.RequestID, created.Status)
		return 0
	}
	fmt.Fprintf(c.stderr, "request_id: %s\nstatus: SUBMITTED\n", created.RequestID)

	outcome, err := client.waitRequestWithOptions(created.RequestID, requestWaitOptions{
		PollInterval:     *pollInterval,
		WaitTimeout:      *waitTimeout,
		StatusInterval:   *statusInterval,
		ReconnectTimeout: *reconnectTimeout,
		StatusWriter:     c.stderr,
		OutputWriter:     c.stdout,
		Follow:           true,
		RequestIDPrinted: true,
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "request wait failed: %v\n", err)
		printResumeHint(c.stderr, created.RequestID, *name, resolvedHost)
		return 1
	}
	printRequestReport(c.stdout, outcome.Record, outcome.LiveOutputPrinted)
	return requestExitCode(outcome.Record)
}

func (c *RequestCmd) runWait(args []string) int {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(c.stderr, "usage: racg request wait <request_id> [--name profile] [--wait-timeout 30m]")
		return 2
	}
	requestID := strings.TrimSpace(args[0])

	fs := flag.NewFlagSet("racg request wait", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum local time to wait; does not cancel the remote request")
	statusInterval := fs.Duration("status-interval", 30*time.Second, "heartbeat interval while status is unchanged; 0 disables")
	reconnectTimeout := fs.Duration("reconnect-timeout", 5*time.Minute, "maximum time to restore observation after a connection failure")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	resolvedHost, resolvedToken, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintln(c.stderr, err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintln(c.stderr, err)
		return 2
	}

	outcome, err := client.waitRequestWithOptions(requestID, requestWaitOptions{
		PollInterval:     *pollInterval,
		WaitTimeout:      *waitTimeout,
		StatusInterval:   *statusInterval,
		ReconnectTimeout: *reconnectTimeout,
		StatusWriter:     c.stderr,
		OutputWriter:     c.stdout,
		Follow:           true,
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "request wait failed: %v\n", err)
		printResumeHint(c.stderr, requestID, *name, resolvedHost)
		return 1
	}
	printRequestReport(c.stdout, outcome.Record, outcome.LiveOutputPrinted)
	return requestExitCode(outcome.Record)
}

func (c *RequestCmd) runCancel(args []string) int {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(c.stderr, "usage: racg request cancel <request_id> --host URL --token TOKEN")
		return 2
	}
	requestID := strings.TrimSpace(args[0])

	fs := flag.NewFlagSet("racg request cancel", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	resolvedHost, resolvedToken, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	if err := client.postEmpty("/v1/requests/" + requestID + "/kill"); err != nil {
		fmt.Fprintf(c.stderr, "request cancel failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "request_id: %s\nstatus: cancel_requested\n", requestID)
	return 0
}

func (c *RequestCmd) runLogs(args []string) int {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(c.stderr, "usage: racg request logs <request_id> [--stdout] [--stderr] --host URL --token TOKEN")
		return 2
	}
	requestID := strings.TrimSpace(args[0])

	fs := flag.NewFlagSet("racg request logs", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	stdoutOnly := fs.Bool("stdout", false, "print stdout only")
	stderrOnly := fs.Bool("stderr", false, "print stderr only")
	live := fs.Bool("live", false, "print current live combined output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	resolvedHost, resolvedToken, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}

	if *live {
		text, err := client.getRequestLog(requestID, "live")
		if err != nil {
			fmt.Fprintf(c.stderr, "request logs failed: %v\n", err)
			return 1
		}
		fmt.Fprint(c.stdout, text)
		return 0
	}

	if *stdoutOnly || *stderrOnly {
		if *stdoutOnly {
			text, err := client.getRequestLog(requestID, "stdout")
			if err != nil {
				fmt.Fprintf(c.stderr, "request logs failed: %v\n", err)
				return 1
			}
			fmt.Fprint(c.stdout, text)
		}
		if *stderrOnly {
			text, err := client.getRequestLog(requestID, "stderr")
			if err != nil {
				fmt.Fprintf(c.stderr, "request logs failed: %v\n", err)
				return 1
			}
			fmt.Fprint(c.stdout, text)
		}
		return 0
	}

	stdoutText, err := client.getRequestLog(requestID, "stdout")
	if err != nil {
		fmt.Fprintf(c.stderr, "request logs failed: %v\n", err)
		return 1
	}
	stderrText, err := client.getRequestLog(requestID, "stderr")
	if err != nil {
		fmt.Fprintf(c.stderr, "request logs failed: %v\n", err)
		return 1
	}
	printStreamSection(c.stdout, "stdout", stdoutText)
	printStreamSection(c.stdout, "stderr", stderrText)
	return 0
}

func (c *RequestCmd) runTail(args []string) int {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(c.stderr, "usage: racg request tail <request_id> --host URL --token TOKEN")
		return 2
	}
	requestID := strings.TrimSpace(args[0])

	fs := flag.NewFlagSet("racg request tail", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while tailing")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	resolvedHost, resolvedToken, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	if *pollInterval <= 0 {
		*pollInterval = 500 * time.Millisecond
	}

	printed := 0
	for {
		text, err := client.getRequestLog(requestID, "live")
		if err != nil {
			fmt.Fprintf(c.stderr, "request tail failed: %v\n", err)
			return 1
		}
		if len(text) > printed {
			fmt.Fprint(c.stdout, text[printed:])
			printed = len(text)
		}
		rec, err := client.getRequest(requestID)
		if err != nil {
			fmt.Fprintf(c.stderr, "request tail failed: %v\n", err)
			return 1
		}
		if isTerminalStatus(rec.Status) {
			text, err := client.getRequestLog(requestID, "live")
			if err == nil && len(text) > printed {
				fmt.Fprint(c.stdout, text[printed:])
			}
			return 0
		}
		time.Sleep(*pollInterval)
	}
}

type racgClient struct {
	baseURL string
	token   string
	http    *http.Client
}

type requestCreateResp struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

type requestStatusResp struct {
	RequestID string          `json:"request_id"`
	Status    string          `json:"status"`
	CreatedAt string          `json:"created_at"`
	Decision  *decisionStatus `json:"decision"`
	Result    *resultStatus   `json:"result"`
}

type decisionStatus struct {
	Decision       string `json:"decision"`
	DecisionSource string `json:"decision_source"`
	DecidedAt      string `json:"decided_at"`
	RuleID         string `json:"rule_id"`
}

type resultStatus struct {
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	DurationMs      int64  `json:"duration_ms"`
	ExitCode        int    `json:"exit_code"`
	Status          string `json:"status"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

type requestWaitOptions struct {
	PollInterval     time.Duration
	WaitTimeout      time.Duration
	StatusInterval   time.Duration
	ReconnectTimeout time.Duration
	StatusWriter     io.Writer
	OutputWriter     io.Writer
	Follow           bool
	RequestIDPrinted bool
}

type requestWaitOutcome struct {
	Record            requestStatusResp
	LiveOutputPrinted bool
}

type httpStatusError struct {
	StatusCode int
	Body       string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("http %d: %s", e.StatusCode, e.Body)
}

type sessionMeResp struct {
	SessionID     string `json:"session_id"`
	ClientID      string `json:"client_id"`
	ExpiresAt     string `json:"expires_at"`
	PrivilegeMode string `json:"privilege_mode"`
}

func newRACGClient(host, token string) (*racgClient, error) {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	if host == "" {
		return nil, errors.New("host is required")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("token is required; pass --token or set RACG_TOKEN")
	}
	return &racgClient{baseURL: host, token: strings.TrimSpace(token), http: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *racgClient) createRequest(body map[string]any) (requestCreateResp, error) {
	var out requestCreateResp
	if err := c.doJSON(http.MethodPost, "/v1/requests", body, &out); err != nil {
		return requestCreateResp{}, err
	}
	if out.RequestID == "" {
		return requestCreateResp{}, errors.New("server response missing request_id")
	}
	return out, nil
}

func (c *racgClient) getRequest(requestID string) (requestStatusResp, error) {
	return c.getRequestContext(context.Background(), requestID)
}

func (c *racgClient) getRequestContext(ctx context.Context, requestID string) (requestStatusResp, error) {
	var out requestStatusResp
	if err := c.doJSONContext(ctx, http.MethodGet, "/v1/requests/"+requestID, nil, &out); err != nil {
		return requestStatusResp{}, err
	}
	if out.RequestID == "" {
		out.RequestID = requestID
	}
	return out, nil
}

func (c *racgClient) getRequestLog(requestID string, stream string) (string, error) {
	return c.getRequestLogContext(context.Background(), requestID, stream)
}

func (c *racgClient) getRequestLogContext(ctx context.Context, requestID string, stream string) (string, error) {
	return c.doTextContext(ctx, http.MethodGet, "/v1/requests/"+requestID+"/logs/"+stream, nil)
}

func (c *racgClient) sessionMe() (sessionMeResp, error) {
	var out sessionMeResp
	if err := c.doJSON(http.MethodGet, "/v1/session/me", nil, &out); err != nil {
		return sessionMeResp{}, err
	}
	return out, nil
}

func (c *racgClient) waitRequest(requestID string, pollInterval, waitTimeout time.Duration) (requestStatusResp, error) {
	outcome, err := c.waitRequestWithOptions(requestID, requestWaitOptions{
		PollInterval: pollInterval,
		WaitTimeout:  waitTimeout,
	})
	return outcome.Record, err
}

func (c *racgClient) waitRequestWithOptions(requestID string, opts requestWaitOptions) (requestWaitOutcome, error) {
	if opts.PollInterval <= 0 {
		opts.PollInterval = 500 * time.Millisecond
	}
	started := time.Now()
	deadline := time.Time{}
	if opts.WaitTimeout > 0 {
		deadline = started.Add(opts.WaitTimeout)
	}
	waitCtx := context.Background()
	cancelWait := func() {}
	if !deadline.IsZero() {
		waitCtx, cancelWait = context.WithDeadline(waitCtx, deadline)
	}
	defer cancelWait()
	lastStatus := ""
	lastNotice := started
	connectionLostAt := time.Time{}
	printedLiveBytes := 0
	liveOutputPrinted := false
	requestIDPrinted := opts.RequestIDPrinted

	for {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return requestWaitOutcome{}, fmt.Errorf("timed out waiting for %s, last status %s", requestID, statusOrUnknown(lastStatus))
		}

		rec, err := c.getRequestContext(waitCtx, requestID)
		if err != nil {
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return requestWaitOutcome{}, fmt.Errorf("timed out waiting for %s, last status %s", requestID, statusOrUnknown(lastStatus))
			}
			if !isRetryableWaitError(err) {
				return requestWaitOutcome{}, err
			}
			now := time.Now()
			if connectionLostAt.IsZero() {
				connectionLostAt = now
				printConnectionStatus(opts.StatusWriter, requestID, "CONNECTION_LOST", err)
			}
			if opts.ReconnectTimeout <= 0 || now.Sub(connectionLostAt) >= opts.ReconnectTimeout {
				return requestWaitOutcome{}, fmt.Errorf("connection was not restored within %s: %w", opts.ReconnectTimeout, err)
			}
			sleepUntilNextPoll(opts.PollInterval, deadline)
			continue
		}

		if !connectionLostAt.IsZero() {
			printConnectionStatus(opts.StatusWriter, requestID, "CONNECTION_RESTORED", nil)
			connectionLostAt = time.Time{}
			lastStatus = ""
		}

		now := time.Now()
		if rec.Status != lastStatus {
			printWaitStatus(opts.StatusWriter, rec, now.Sub(started), !requestIDPrinted)
			requestIDPrinted = true
			lastStatus = rec.Status
			lastNotice = now
		}

		if opts.Follow && !isTerminalStatus(rec.Status) {
			text, logErr := c.getRequestLogContext(waitCtx, requestID, "live")
			if logErr == nil {
				if len(text) < printedLiveBytes {
					printedLiveBytes = 0
				}
				if len(text) > printedLiveBytes {
					fmt.Fprint(opts.OutputWriter, text[printedLiveBytes:])
					printedLiveBytes = len(text)
					liveOutputPrinted = true
				}
			}
		}

		if isTerminalStatus(rec.Status) {
			if opts.Follow {
				if text, logErr := c.getRequestLogContext(waitCtx, requestID, "live"); logErr == nil {
					if len(text) < printedLiveBytes {
						printedLiveBytes = 0
					}
					if len(text) > printedLiveBytes {
						fmt.Fprint(opts.OutputWriter, text[printedLiveBytes:])
						liveOutputPrinted = true
					}
				}
			}
			return requestWaitOutcome{Record: rec, LiveOutputPrinted: liveOutputPrinted}, nil
		}

		if opts.StatusInterval > 0 && now.Sub(lastNotice) >= opts.StatusInterval {
			if opts.StatusWriter != nil {
				fmt.Fprintf(opts.StatusWriter, "[%s] %s\n", now.Format("15:04:05"), waitHeartbeatText(rec.Status, now.Sub(started)))
			}
			lastNotice = now
		}
		sleepUntilNextPoll(opts.PollInterval, deadline)
	}
}

func sleepUntilNextPoll(interval time.Duration, deadline time.Time) {
	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		if interval > remaining {
			interval = remaining
		}
	}
	time.Sleep(interval)
}

func isRetryableWaitError(err error) bool {
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == http.StatusRequestTimeout || statusErr.StatusCode == http.StatusTooManyRequests || statusErr.StatusCode >= 500
	}
	return true
}

func statusOrUnknown(status string) string {
	if status == "" {
		return "UNKNOWN"
	}
	return status
}

func (c *racgClient) postEmpty(path string) error {
	var out map[string]any
	return c.doJSON(http.MethodPost, path, map[string]any{}, &out)
}

func (c *racgClient) doJSON(method, path string, body any, out any) error {
	return c.doJSONContext(context.Background(), method, path, body, out)
}

func (c *racgClient) doJSONContext(ctx context.Context, method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpStatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return err
	}
	return nil
}

func (c *racgClient) doText(method, path string, body any) (string, error) {
	return c.doTextContext(context.Background(), method, path, body)
}

func (c *racgClient) doTextContext(ctx context.Context, method, path string, body any) (string, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, r)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &httpStatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
	}
	return string(respBody), nil
}

func printRequestResult(w io.Writer, rec requestStatusResp) {
	fmt.Fprintf(w, "request_id: %s\n", rec.RequestID)
	fmt.Fprintf(w, "status: %s\n", rec.Status)
	if rec.Result == nil {
		return
	}
	fmt.Fprintf(w, "exit_code: %d\n", rec.Result.ExitCode)
	printStreamSection(w, "stdout", rec.Result.Stdout)
	printStreamSection(w, "stderr", rec.Result.Stderr)
}

func printWaitStatus(w io.Writer, rec requestStatusResp, elapsed time.Duration, includeRequestID bool) {
	if w == nil {
		return
	}
	if includeRequestID {
		fmt.Fprintf(w, "request_id: %s\n", rec.RequestID)
	}
	fmt.Fprintf(w, "status: %s\n", rec.Status)
	if waitingFor := waitingForStatus(rec.Status); waitingFor != "" {
		fmt.Fprintf(w, "waiting_for: %s\n", waitingFor)
	}
	fmt.Fprintf(w, "elapsed: %s\n", formatDuration(elapsed))
}

func printConnectionStatus(w io.Writer, requestID, status string, err error) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "request_id: %s\nstatus: %s\n", requestID, status)
	if err != nil {
		fmt.Fprintf(w, "reason: %v\n", err)
	}
}

func waitingForStatus(status string) string {
	switch status {
	case "PENDING_APPROVAL":
		return "server approval"
	case "APPROVED":
		return "execution queue"
	case "QUEUED":
		return "execution slot"
	case "RUNNING":
		return "remote process"
	default:
		return ""
	}
}

func waitHeartbeatText(status string, elapsed time.Duration) string {
	state := "request status is " + statusOrUnknown(status)
	switch status {
	case "PENDING_APPROVAL":
		state = "request is still pending approval"
	case "APPROVED":
		state = "request is approved and waiting for execution"
	case "QUEUED":
		state = "request is still queued for execution"
	case "RUNNING":
		state = "request is still running without new status"
	}
	return fmt.Sprintf("%s (elapsed %s)", state, formatDuration(elapsed))
}

func printResumeHint(w io.Writer, requestID, profileName, host string) {
	if w == nil {
		return
	}
	fmt.Fprintln(w, "Local waiting stopped.")
	fmt.Fprintln(w, "The remote request was not cancelled.")
	fmt.Fprintln(w, "Resume:")
	command := "  racg request wait " + requestID
	if strings.TrimSpace(profileName) != "" {
		command += " --name " + quoteCLIArg(profileName)
	} else if strings.TrimSpace(host) != "" {
		command += " --host " + quoteCLIArg(host)
	}
	fmt.Fprintln(w, command)
}

func quoteCLIArg(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\r\n'\"") {
		return value
	}
	return fmt.Sprintf("%q", value)
}

func printRequestReport(w io.Writer, rec requestStatusResp, liveOutputPrinted bool) {
	fmt.Fprintf(w, "\nRequest: %s\n", rec.RequestID)
	fmt.Fprintf(w, "Status: %s\n", rec.Status)
	if rec.CreatedAt != "" {
		fmt.Fprintf(w, "\nSubmitted: %s\n", rec.CreatedAt)
	}
	if rec.Decision != nil && rec.Decision.DecidedAt != "" {
		fmt.Fprintf(w, "Approved:  %s\n", rec.Decision.DecidedAt)
	}
	if rec.Result != nil && rec.Result.StartedAt != "" {
		fmt.Fprintf(w, "Started:   %s\n", rec.Result.StartedAt)
	}
	if rec.Result != nil && rec.Result.FinishedAt != "" {
		fmt.Fprintf(w, "Finished:  %s\n", rec.Result.FinishedAt)
	}

	createdAt, createdOK := parseAPITime(rec.CreatedAt)
	decidedAt, decidedOK := time.Time{}, false
	if rec.Decision != nil {
		decidedAt, decidedOK = parseAPITime(rec.Decision.DecidedAt)
	}
	startedAt, startedOK := time.Time{}, false
	finishedAt, finishedOK := time.Time{}, false
	if rec.Result != nil {
		startedAt, startedOK = parseAPITime(rec.Result.StartedAt)
		finishedAt, finishedOK = parseAPITime(rec.Result.FinishedAt)
	}
	if createdOK && decidedOK {
		fmt.Fprintf(w, "\nApproval wait: %s\n", formatDuration(decidedAt.Sub(createdAt)))
	}
	if decidedOK && startedOK {
		fmt.Fprintf(w, "Queue wait: %s\n", formatDuration(startedAt.Sub(decidedAt)))
	}
	if rec.Result != nil {
		execution := time.Duration(rec.Result.DurationMs) * time.Millisecond
		if execution <= 0 && startedOK && finishedOK {
			execution = finishedAt.Sub(startedAt)
		}
		fmt.Fprintf(w, "Execution: %s\n", formatDuration(execution))
		fmt.Fprintf(w, "\nExit code: %d\n", rec.Result.ExitCode)
		fmt.Fprintf(w, "Stdout: %s\n", formatByteSize(len(rec.Result.Stdout)))
		fmt.Fprintf(w, "Stderr: %s\n", formatByteSize(len(rec.Result.Stderr)))
		truncated := rec.Result.StdoutTruncated || rec.Result.StderrTruncated
		fmt.Fprintf(w, "Output truncated: %s\n", yesNo(truncated))
		if !liveOutputPrinted {
			fmt.Fprintln(w)
			printStreamSection(w, "stdout", rec.Result.Stdout)
			printStreamSection(w, "stderr", rec.Result.Stderr)
		}
	}
}

func parseAPITime(value string) (time.Time, bool) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil
}

func formatDuration(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	return value.Round(time.Millisecond).String()
}

func formatByteSize(size int) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	return fmt.Sprintf("%.1f KiB", float64(size)/1024)
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func requestExitCode(rec requestStatusResp) int {
	if rec.Result != nil {
		return normalizeExitCode(rec.Result.ExitCode)
	}
	return 1
}

func printStreamSection(w io.Writer, name, text string) {
	fmt.Fprintf(w, "%s:\n", name)
	fmt.Fprint(w, text)
	if text == "" || !strings.HasSuffix(text, "\n") {
		fmt.Fprintln(w)
	}
}

func isTerminalStatus(status string) bool {
	switch status {
	case "SUCCEEDED", "FAILED", "TIMED_OUT", "KILLED", "DENIED", "CANCELED":
		return true
	default:
		return false
	}
}

func normalizeExitCode(code int) int {
	if code >= 0 && code <= 255 {
		return code
	}
	return 1
}

func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
