package cli

import (
	"bytes"
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
		fmt.Fprintln(c.stderr, "usage: racg request <cancel|logs|tail> [args]")
		return 2
	}

	switch args[0] {
	case "cancel":
		return c.runCancel(args[1:])
	case "logs":
		return c.runLogs(args[1:])
	case "tail":
		return c.runTail(args[1:])
	default:
		fmt.Fprintln(c.stderr, "usage: racg request <cancel|logs|tail> [args]")
		return 2
	}
}

func (c *RequestCmd) RunRun(args []string) int {
	fs := flag.NewFlagSet("racg run", flag.ContinueOnError)
	fs.SetOutput(c.stderr)

	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	cwd := fs.String("cwd", "", "command working directory")
	timeoutSec := fs.Int("timeout", 0, "command timeout in seconds")
	noWait := fs.Bool("no-wait", false, "create request and print request id without waiting")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")

	if err := fs.Parse(args); err != nil {
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
	if *timeoutSec > 0 {
		payload["timeout_sec"] = *timeoutSec
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

	rec, err := client.waitRequest(created.RequestID, *pollInterval, *waitTimeout)
	if err != nil {
		fmt.Fprintf(c.stderr, "request wait failed: %v\n", err)
		return 1
	}
	printRequestResult(c.stdout, rec)
	if rec.Status == "SUCCEEDED" && rec.Result != nil {
		return normalizeExitCode(rec.Result.ExitCode)
	}
	return 1
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
	RequestID string        `json:"request_id"`
	Status    string        `json:"status"`
	Result    *resultStatus `json:"result"`
}

type resultStatus struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
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
	var out requestStatusResp
	if err := c.doJSON(http.MethodGet, "/v1/requests/"+requestID, nil, &out); err != nil {
		return requestStatusResp{}, err
	}
	if out.RequestID == "" {
		out.RequestID = requestID
	}
	return out, nil
}

func (c *racgClient) getRequestLog(requestID string, stream string) (string, error) {
	return c.doText(http.MethodGet, "/v1/requests/"+requestID+"/logs/"+stream, nil)
}

func (c *racgClient) sessionMe() (sessionMeResp, error) {
	var out sessionMeResp
	if err := c.doJSON(http.MethodGet, "/v1/session/me", nil, &out); err != nil {
		return sessionMeResp{}, err
	}
	return out, nil
}

func (c *racgClient) waitRequest(requestID string, pollInterval, waitTimeout time.Duration) (requestStatusResp, error) {
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	var deadline time.Time
	if waitTimeout > 0 {
		deadline = time.Now().Add(waitTimeout)
	}
	for {
		rec, err := c.getRequest(requestID)
		if err != nil {
			return requestStatusResp{}, err
		}
		if isTerminalStatus(rec.Status) {
			return rec, nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return requestStatusResp{}, fmt.Errorf("timed out waiting for %s, last status %s", requestID, rec.Status)
		}
		time.Sleep(pollInterval)
	}
}

func (c *racgClient) postEmpty(path string) error {
	var out map[string]any
	return c.doJSON(http.MethodPost, path, map[string]any{}, &out)
}

func (c *racgClient) doJSON(method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, r)
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
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
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
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, r)
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
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
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
	if code >= 0 && code <= 125 {
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
