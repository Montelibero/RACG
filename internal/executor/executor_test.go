package executor

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestRunEcho(t *testing.T) {
	if _, err := exec.LookPath("/bin/echo"); err != nil {
		t.Skip("/bin/echo not found")
	}

	ex := New(Options{MaxOutputBytes: 1024, KillGrace: 50 * time.Millisecond})
	res := ex.Run(context.Background(), Spec{Argv: []string{"/bin/echo", "hi"}, Timeout: 2 * time.Second})

	if res.Status != "SUCCEEDED" {
		t.Fatalf("Status=%q", res.Status)
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode=%d", res.ExitCode)
	}
	if res.Stdout != "hi\n" {
		t.Fatalf("Stdout=%q", res.Stdout)
	}
	if res.StdoutSHA256 == "" {
		t.Fatalf("missing stdout sha")
	}
}

func TestTimeout(t *testing.T) {
	if _, err := exec.LookPath("/bin/sleep"); err != nil {
		t.Skip("/bin/sleep not found")
	}

	ex := New(Options{MaxOutputBytes: 1024, KillGrace: 50 * time.Millisecond})
	res := ex.Run(context.Background(), Spec{Argv: []string{"/bin/sleep", "2"}, Timeout: 50 * time.Millisecond})
	if res.Status != "TIMED_OUT" {
		t.Fatalf("Status=%q", res.Status)
	}
}

func TestKill(t *testing.T) {
	if _, err := exec.LookPath("/bin/sleep"); err != nil {
		t.Skip("/bin/sleep not found")
	}

	ex := New(Options{MaxOutputBytes: 1024, KillGrace: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	res := ex.Run(ctx, Spec{Argv: []string{"/bin/sleep", "2"}, Timeout: 2 * time.Second})
	if res.Status != "KILLED" {
		t.Fatalf("Status=%q", res.Status)
	}
}

func TestOutputTruncation(t *testing.T) {
	if _, err := exec.LookPath("yes"); err != nil {
		t.Skip("yes not found")
	}

	ex := New(Options{MaxOutputBytes: 64, KillGrace: 50 * time.Millisecond})
	res := ex.Run(context.Background(), Spec{Argv: []string{"yes"}, Timeout: 50 * time.Millisecond})
	if !res.StdoutTruncated {
		t.Fatalf("expected stdout truncated")
	}
	if res.StdoutSHA256 == "" {
		t.Fatalf("missing stdout sha")
	}
	if res.Status != "TIMED_OUT" {
		t.Fatalf("Status=%q", res.Status)
	}
}
