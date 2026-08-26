package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os/exec"
	"syscall"
	"time"
)

type Options struct {
	MaxOutputBytes int
	KillGrace      time.Duration
}

type Executor struct {
	opts Options
}

type Spec struct {
	Argv    []string
	Cwd     string
	Stdin   io.Reader
	Timeout time.Duration

	// Optional streaming callbacks (used by TUI for live output).
	OnStdout func([]byte)
	OnStderr func([]byte)
}

type Result struct {
	Status          string
	ExitCode        int
	DurationMs      int64
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	StdoutSHA256    string
	StderrSHA256    string
}

func New(opts Options) *Executor {
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = 1 * 1024 * 1024
	}
	if opts.KillGrace <= 0 {
		opts.KillGrace = 3 * time.Second
	}
	return &Executor{opts: opts}
}

func (e *Executor) Run(ctx context.Context, s Spec) Result {
	start := time.Now()
	res := Result{Status: "FAILED", ExitCode: -1}

	if len(s.Argv) == 0 || s.Argv[0] == "" {
		res.Stderr = "missing argv"
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	tctx := ctx
	cancel := func() {}
	if s.Timeout > 0 {
		tctx, cancel = context.WithTimeout(ctx, s.Timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(tctx, s.Argv[0], s.Argv[1:]...)
	if s.Cwd != "" {
		cmd.Dir = s.Cwd
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutCap := newStreamCapture(e.opts.MaxOutputBytes, s.OnStdout)
	stderrCap := newStreamCapture(e.opts.MaxOutputBytes, s.OnStderr)
	cmd.Stdout = stdoutCap
	cmd.Stderr = stderrCap
	cmd.Stdin = s.Stdin

	if err := cmd.Start(); err != nil {
		res.Stderr = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	// If the context is canceled/deadline-exceeded, attempt to kill the whole process group ASAP.
	killOnce := make(chan struct{})
	go func() {
		select {
		case <-tctx.Done():
			_ = killProcessGroup(cmd.Process.Pid, e.opts.KillGrace)
		case <-killOnce:
		}
	}()

	waitErr := cmd.Wait()
	close(killOnce)

	// If context deadline hit, ensure the whole process group is dead.
	if tctx.Err() != nil {
		_ = killProcessGroup(cmd.Process.Pid, e.opts.KillGrace)
	}

	res.Stdout, res.StdoutSHA256, res.StdoutTruncated = stdoutCap.result()
	res.Stderr, res.StderrSHA256, res.StderrTruncated = stderrCap.result()

	res.DurationMs = time.Since(start).Milliseconds()

	if tctx.Err() != nil {
		if errors.Is(tctx.Err(), context.Canceled) {
			res.Status = "KILLED"
		} else {
			res.Status = "TIMED_OUT"
		}
		res.ExitCode = -1
		return res
	}

	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			// Go sets Sys() to syscall.WaitStatus on Unix.
			if st, ok := ee.Sys().(syscall.WaitStatus); ok {
				exitCode = st.ExitStatus()
			} else {
				exitCode = 1
			}
		} else {
			exitCode = 1
		}
	}
	res.ExitCode = exitCode
	if waitErr == nil {
		res.Status = "SUCCEEDED"
	} else {
		res.Status = "FAILED"
	}
	return res
}

type streamCapture struct {
	max      int
	onChunk  func([]byte)
	hash     hash.Hash
	buf      bytes.Buffer
	stored   int
	truncate bool
}

func newStreamCapture(max int, onChunk func([]byte)) *streamCapture {
	return &streamCapture{max: max, onChunk: onChunk, hash: sha256.New()}
}

func (c *streamCapture) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.onChunk != nil {
		cp := append([]byte(nil), p...)
		c.onChunk(cp)
	}
	_, _ = c.hash.Write(p)

	if c.stored < c.max {
		remain := c.max - c.stored
		if len(p) <= remain {
			_, _ = c.buf.Write(p)
			c.stored += len(p)
		} else {
			_, _ = c.buf.Write(p[:remain])
			c.stored += remain
			c.truncate = true
		}
	} else {
		c.truncate = true
	}
	return len(p), nil
}

func (c *streamCapture) result() (text string, shaHex string, truncated bool) {
	return c.buf.String(), hex.EncodeToString(c.hash.Sum(nil)), c.truncate
}

func killProcessGroup(pid int, grace time.Duration) error {
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return err
	}
	// Negative pid means process group.
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	if grace > 0 {
		t := time.NewTimer(grace)
		<-t.C
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	return nil
}
