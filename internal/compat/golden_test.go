// Package compat runs golden contract tests: real released client binaries
// against the current server composition (privileged pipeline behind the
// unprivileged remote-approver facade).
//
// Opt-in because it shells out to git and the Go toolchain:
//
//	RACG_GOLDEN=1 go test ./internal/compat
package compat

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Wire-format constants are pinned here independently of internal/httpapi:
// the golden test must verify the contract, not import the implementation.
const (
	pairingDomain  = "racg/approver/pairing/v1"
	pollDomain     = "racg/approver/poll/v1"
	decisionDomain = "racg/approver/decision/v1"
)

type goldenProc struct {
	cmd    *exec.Cmd
	stdout *lineBuffer
	stderr *lineBuffer
}

type lineBuffer struct {
	b      bytes.Buffer
	notify chan struct{}
}

func (l *lineBuffer) Write(p []byte) (int, error) {
	n, err := l.b.Write(p)
	if bytes.ContainsRune(p, '\n') {
		select {
		case l.notify <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (l *lineBuffer) lines() []string {
	return strings.Split(strings.TrimRight(l.b.String(), "\n"), "\n")
}

func (l *lineBuffer) value(t *testing.T, key string, deadline time.Duration) string {
	t.Helper()
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(key) + `=(.*)$`)
	at := time.Now().Add(deadline)
	for {
		for _, line := range l.lines() {
			if m := re.FindStringSubmatch(line); m != nil {
				return m[1]
			}
		}
		if time.Now().After(at) {
			t.Fatalf("timed out waiting for %q in output:\n%s", key, l.b.String())
		}
		select {
		case <-l.notify:
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (l *lineBuffer) text() string { return l.b.String() }

func startGoldenProc(t *testing.T, ctx context.Context, dir string, env []string, args ...string) *goldenProc {
	t.Helper()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	p := &goldenProc{
		cmd:    cmd,
		stdout: &lineBuffer{notify: make(chan struct{}, 64)},
		stderr: &lineBuffer{notify: make(chan struct{}, 64)},
	}
	cmd.Stdout = p.stdout
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %v: %v", args, err)
	}
	t.Cleanup(func() {
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
			_, _ = p.cmd.Process.Wait()
		}
		t.Logf("proc %v exit-state\n--- stdout ---\n%s\n--- stderr ---\n%s", args, p.stdout.text(), p.stderr.text())
	})
	return p
}

func runGoldenCmd(t *testing.T, ctx context.Context, dir string, env []string, timeout time.Duration, args ...string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return out.String(), errb.String(), code
}

func TestGoldenV05ClientThroughFacade(t *testing.T) {
	if os.Getenv("RACG_GOLDEN") == "" {
		t.Skip("golden contract test is opt-in: run with RACG_GOLDEN=1")
	}
	ctx := context.Background()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()

	// Build the current server binary.
	out, errb, code := runGoldenCmd(t, ctx, root, []string{"GOTOOLCHAIN=local"}, 3*time.Minute,
		goBin, "build", "-o", filepath.Join(base, "racg-new"), "./cmd/racg")
	if code != 0 {
		t.Fatalf("build current binary: %s%s", out, errb)
	}

	// Build the real v0.5.0 client from the tag.
	src := filepath.Join(base, "v05src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if outb, err := exec.Command(gitBin, "-C", root, "archive", "--format=tar", "-o", filepath.Join(base, "v05.tar"), "v0.5.0").CombinedOutput(); err != nil {
		t.Skipf("v0.5.0 tag unavailable: %v: %s", err, outb)
	}
	if outb, err := exec.Command("tar", "-xf", filepath.Join(base, "v05.tar"), "-C", src).CombinedOutput(); err != nil {
		t.Fatalf("extract v0.5.0: %v: %s", err, outb)
	}
	out, errb, code = runGoldenCmd(t, ctx, src, []string{"GOTOOLCHAIN=local", "GOFLAGS=-mod=mod"}, 5*time.Minute,
		goBin, "build", "-o", filepath.Join(base, "racg-old"), "./cmd/racg")
	if code != 0 {
		t.Fatalf("build v0.5.0 client: %s%s", out, errb)
	}

	// Start the privileged pipeline: unix socket only, no public port.
	configPath := filepath.Join(base, "config.toml")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("db_path = %q\n", filepath.Join(base, "racg.db"))), 0o600); err != nil {
		t.Fatal(err)
	}
	pipeline := startGoldenProc(t, ctx, root, nil,
		filepath.Join(base, "racg-new"), "serve",
		"--headless", "--socket", filepath.Join(base, "pipeline.sock"),
		"--server-id", "golden", "--config", configPath)
	pipeline.stdout.value(t, "pipeline_ready", 15*time.Second)
	pairingCode := pipeline.stdout.value(t, "pairing_code", 5*time.Second)
	approverToken := pipeline.stdout.value(t, "approver_pairing_token", 5*time.Second)

	// Start the unprivileged facade: the only public listener.
	facade := startGoldenProc(t, ctx, root, nil,
		filepath.Join(base, "racg-new"), "remote-approver",
		"--listen", "127.0.0.1:0", "--socket", filepath.Join(base, "pipeline.sock"))
	facadeAddr := facade.stdout.value(t, "listen", 10*time.Second)
	baseURL := "http://" + facadeAddr

	clientEnv := []string{
		"XDG_CONFIG_HOME=" + filepath.Join(base, "client"),
		"RACG_CLIENT_NAME=golden",
	}

	// 1. Real v0.5.0 login through the facade.
	out, errb, code = runGoldenCmd(t, ctx, base, clientEnv, 30*time.Second,
		filepath.Join(base, "racg-old"),
		"login", "--host", baseURL, "--pairing-code", pairingCode, "--name", "golden")
	if code != 0 {
		t.Fatalf("v0.5 login failed: %s%s", out, errb)
	}

	// Enroll an approver device through the same public facade.
	device := newGoldenDevice(t, "golden-device")
	pairGoldenDevice(t, baseURL, "golden", device, approverToken)

	// 2. Real v0.5.0 run approved by the enrolled device.
	out, _, code = runGoldenCmd(t, ctx, base, clientEnv, 30*time.Second,
		filepath.Join(base, "racg-old"),
		"run", "--name", "golden", "--no-wait", "--", "/bin/echo", "golden-smoke-marker")
	if code != 0 {
		t.Fatalf("v0.5 run --no-wait failed: %s%s", out, errb)
	}
	requestID := goldenOutputValue(t, out, "request_id")
	approveGoldenPending(t, baseURL, "golden", device, "ALLOW_ONCE")

	out, errb, code = runGoldenCmd(t, ctx, base, clientEnv, 60*time.Second,
		filepath.Join(base, "racg-old"), "request", "wait", requestID)
	if code != 0 {
		t.Fatalf("v0.5 request wait after approval: code=%d out=%s err=%s", code, out, errb)
	}
	if !strings.Contains(out, "SUCCEEDED") {
		t.Fatalf("expected SUCCEEDED in wait output: %s", out)
	}

	// 3. Result output reaches the old client through the facade.
	out, errb, code = runGoldenCmd(t, ctx, base, clientEnv, 30*time.Second,
		filepath.Join(base, "racg-old"), "request", "logs", requestID, "--stdout", "--unredacted")
	if code != 0 || !strings.Contains(out+errb, "golden-smoke-marker") {
		t.Fatalf("request logs: code=%d out=%s err=%s", code, out, errb)
	}

	// 4. Second run denied by the device: old client sees the denial.
	out, _, code = runGoldenCmd(t, ctx, base, clientEnv, 30*time.Second,
		filepath.Join(base, "racg-old"),
		"run", "--name", "golden", "--no-wait", "--", "/bin/echo", "should-not-run")
	if code != 0 {
		t.Fatalf("v0.5 run --no-wait (deny case) failed: %s%s", out, errb)
	}
	deniedID := goldenOutputValue(t, out, "request_id")
	approveGoldenPending(t, baseURL, "golden", device, "DENY")

	out, errb, code = runGoldenCmd(t, ctx, base, clientEnv, 60*time.Second,
		filepath.Join(base, "racg-old"), "request", "wait", deniedID)
	if code == 0 {
		t.Fatalf("denied request wait unexpectedly succeeded: %s%s", out, errb)
	}
	combined := out + errb
	if !strings.Contains(combined, "DENIED") {
		t.Fatalf("denial not visible to v0.5 client: %s", combined)
	}
}

func goldenOutputValue(t *testing.T, output, key string) string {
	t.Helper()
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(key) + `:\s*(\S+)`)
	for _, line := range strings.Split(output, "\n") {
		if m := re.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			return m[1]
		}
	}
	t.Fatalf("no %q in output:\n%s", key, output)
	return ""
}

type goldenDevice struct {
	id     string
	priv   *ecdsa.PrivateKey
	pubDER []byte
}

func newGoldenDevice(t *testing.T, id string) *goldenDevice {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &goldenDevice{id: id, priv: priv, pubDER: pubDER}
}

func (d *goldenDevice) sign(t *testing.T, message []byte) string {
	t.Helper()
	hash := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, d.priv, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func goldenMessage(domain, serverID string, parts ...string) []byte {
	message := domain + "\x00" + serverID
	for _, part := range parts {
		message += "\x00" + part
	}
	return []byte(message)
}

func goldenChallenge(t *testing.T, baseURL string) string {
	t.Helper()
	resp, err := http.Get(baseURL + "/v1/approver/challenge")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Challenge == "" {
		t.Fatalf("challenge: %v %s", err, resp.Status)
	}
	return out.Challenge
}

func pairGoldenDevice(t *testing.T, baseURL, serverID string, d *goldenDevice, tokenB64 string) {
	t.Helper()
	challenge := goldenChallenge(t, baseURL)
	token, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		t.Fatalf("server enrollment token is not standard base64: %v", err)
	}
	tokenHash := sha256.Sum256(token)
	pubHash := sha256.Sum256(d.pubDER)
	message := goldenMessage(pairingDomain, serverID, d.id, hex.EncodeToString(pubHash[:]), challenge, hex.EncodeToString(tokenHash[:]))
	body := map[string]any{
		"device_id":    d.id,
		"public_key":   d.pubDER,
		"token_sha256": hex.EncodeToString(tokenHash[:]),
		"challenge":    challenge,
		"signature":    d.sign(t, message),
	}
	postGoldenJSON(t, baseURL+"/v1/approver/pairing", body, http.StatusOK)
}

func approveGoldenPending(t *testing.T, baseURL, serverID string, d *goldenDevice, decision string) {
	t.Helper()
	pollChallenge := goldenChallenge(t, baseURL)
	pollMessage := goldenMessage(pollDomain, serverID, d.id, "/v1/approver/requests", pollChallenge)

	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/approver/requests", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Racg-Approver-Device", d.id)
	req.Header.Set("X-Racg-Approver-Challenge", pollChallenge)
	req.Header.Set("X-Racg-Approver-Signature", d.sign(t, pollMessage))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll: %s %s", resp.Status, raw)
	}
	var list struct {
		Requests []struct {
			ID       string `json:"id"`
			OpSHA256 string `json:"op_sha256"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("poll body: %v: %s", err, raw)
	}
	if len(list.Requests) == 0 {
		t.Fatal("no pending requests visible to the approver")
	}
	target := list.Requests[0]

	decisionChallenge := goldenChallenge(t, baseURL)
	body := map[string]any{
		"device_id":        d.id,
		"request_id":       target.ID,
		"decision":         decision,
		"operation_sha256": target.OpSHA256,
		"challenge":        decisionChallenge,
		"signature":        d.sign(t, goldenMessage(decisionDomain, serverID, d.id, target.ID, target.OpSHA256, decision, decisionChallenge)),
	}
	postGoldenJSON(t, baseURL+"/v1/approver/decision", body, http.StatusOK)
}

func postGoldenJSON(t *testing.T, url string, body map[string]any, wantCode int) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantCode {
		t.Fatalf("%s: got %s want %d: %s", url, resp.Status, wantCode, rawBody)
	}
}
