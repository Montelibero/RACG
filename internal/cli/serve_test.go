package cli

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestServeReturnsWhenListenPortIsAlreadyInUse(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- NewServeCmd(&stdout, &stderr).Run([]string{
			"-listen-addr", "127.0.0.1",
			"-port", strconv.Itoa(port),
		})
	}()

	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit code=%d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "server error:") {
			t.Fatalf("stderr=%q, want server error", stderr.String())
		}
		if strings.Contains(stdout.String(), "listening=") {
			t.Fatalf("stdout reported a listener that never started: %q", stdout.String())
		}
	case <-time.After(time.Second):
		t.Fatal("serve hung after listen failed")
	}
}
