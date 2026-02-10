package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	Timeout time.Duration
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

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		res.Stderr = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		res.Stderr = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	if err := cmd.Start(); err != nil {
		res.Stderr = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	// Capture stdout/stderr concurrently to avoid deadlocks.
	type capRes struct {
		text      string
		hashHex   string
		truncated bool
	}
	outCh := make(chan capRes, 1)
	errCh := make(chan capRes, 1)

	go func() {
		txt, h, trunc := captureLimited(stdoutPipe, e.opts.MaxOutputBytes)
		outCh <- capRes{text: txt, hashHex: h, truncated: trunc}
	}()
	go func() {
		txt, h, trunc := captureLimited(stderrPipe, e.opts.MaxOutputBytes)
		errCh <- capRes{text: txt, hashHex: h, truncated: trunc}
	}()

	waitErr := cmd.Wait()

	// If context deadline hit, ensure the whole process group is dead.
	if tctx.Err() != nil {
		_ = killProcessGroup(cmd.Process.Pid, e.opts.KillGrace)
	}

	out := <-outCh
	errCap := <-errCh

	res.Stdout = out.text
	res.StdoutSHA256 = out.hashHex
	res.StdoutTruncated = out.truncated
	res.Stderr = errCap.text
	res.StderrSHA256 = errCap.hashHex
	res.StderrTruncated = errCap.truncated

	res.DurationMs = time.Since(start).Milliseconds()

	if tctx.Err() != nil {
		res.Status = "TIMED_OUT"
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

func captureLimited(r io.Reader, max int) (text string, shaHex string, truncated bool) {
	h := sha256.New()
	var buf bytes.Buffer

	// Stream copy: store up to max bytes, but hash everything.
	tmp := make([]byte, 32*1024)
	stored := 0
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			chunk := tmp[:n]
			_, _ = h.Write(chunk)

			if stored < max {
				remain := max - stored
				if n <= remain {
					_, _ = buf.Write(chunk)
					stored += n
				} else {
					_, _ = buf.Write(chunk[:remain])
					stored += remain
					truncated = true
				}
			} else {
				truncated = true
			}
		}
		if err != nil {
			break
		}
	}

	return buf.String(), hex.EncodeToString(h.Sum(nil)), truncated
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
