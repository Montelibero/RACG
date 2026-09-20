package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

// RemoteApproverCmd is the unprivileged public facade: the only process with a
// public port. It validates the shape of traffic (known route families, sane
// methods) and reverse-proxies everything to the privileged pipeline over a
// local unix socket. It holds no secrets and cannot authorize anything: the
// pipeline verifies session tokens and approver signatures itself.
type RemoteApproverCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewRemoteApproverCmd(stdout, stderr io.Writer) *RemoteApproverCmd {
	return &RemoteApproverCmd{stdout: stdout, stderr: stderr}
}

func (c *RemoteApproverCmd) Run(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.run(ctx, args)
}

func (c *RemoteApproverCmd) run(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("racg remote-approver", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintln(c.stderr, "usage: racg remote-approver [flags]")
		fmt.Fprintln(c.stderr, "Unprivileged public facade for the privileged pipeline.")
		fmt.Fprintln(c.stderr, "The only public port: proxies the legacy client API and /v1/approver to the pipeline socket.")
		fmt.Fprintln(c.stderr, "Run this under a dedicated unprivileged user; the pipeline stays off the network.")
		fmt.Fprintln(c.stderr, "The facade validates traffic shape only; the pipeline authenticates every request.")
		fs.PrintDefaults()
	}
	listen := fs.String("listen", "127.0.0.1:8777", "the only public listen address (host:port)")
	socket := fs.String("socket", "/run/racg/pipeline.sock", "pipeline unix socket to proxy into")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *socket == "" {
		fmt.Fprintln(c.stderr, "--socket is required")
		return 2
	}

	handler := newRemoteApproverHandler(*socket)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No ReadTimeout or WriteTimeout: uploads, downloads and live output
		// stream for as long as the work runs.
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(c.stderr, "remote-approver listen failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "remote_approver_ready=true\nlisten=%s\nsocket=%s\n", ln.Addr(), *socket)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(c.stderr, "remote-approver error: %v\n", err)
			return 1
		}
		return 0
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(c.stderr, "remote-approver error: %v\n", err)
			return 1
		}
		return 0
	}
}

// remoteApproverAllowedPath matches the frozen v0.4/v0.5 client surface plus
// the approver routes. Anything else is answered 404 without touching the
// pipeline.
var remoteApproverAllowedPath = regexp.MustCompile(
	`^/(healthz|openapi\.json|v1/(info|session|uploads|requests|events|approver)(/|$))`)

var remoteApproverAllowedMethod = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
	http.MethodOptions: true,
}

type remoteApproverHandler struct {
	proxy *httputil.ReverseProxy
}

func newRemoteApproverHandler(socketPath string) http.Handler {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // long-lived endpoints may stay silent while work runs
	}
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "pipeline"
		},
		Transport:     transport,
		FlushInterval: -1, // flush immediately: live output, downloads, WebSocket upgrades
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "PIPELINE_UNAVAILABLE",
				"message": "pipeline socket unreachable",
			})
		},
	}
	return &remoteApproverHandler{proxy: rp}
}

func (h *remoteApproverHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !remoteApproverAllowedPath.MatchString(r.URL.Path) {
		writeFacadeError(w, http.StatusNotFound, "NOT_FOUND", "unknown path")
		return
	}
	if !remoteApproverAllowedMethod[r.Method] {
		writeFacadeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	// The facade owns the forwarding context: a client cannot spoof its IP by
	// pre-setting these headers. ReverseProxy appends the real client address
	// to X-Forwarded-For, which the pipeline trusts only over the unix socket.
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-Ip")
	h.proxy.ServeHTTP(w, r)
}

func writeFacadeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}
