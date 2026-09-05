package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"
)

// ReadFile executes an already-authorized read. The caller supplies the effective
// output limit. Like command execution, this function does not grant permission.
// Output is capped, but its digest covers all bytes read from the file.
func ReadFile(path string, maxBytes int) Result {
	start := time.Now()
	emptySum := sha256.Sum256(nil)
	emptyHash := hex.EncodeToString(emptySum[:])
	res := Result{Status: "FAILED", ExitCode: -1, StdoutSHA256: emptyHash, StderrSHA256: emptyHash}
	fail := func(err error) Result {
		res.Stderr = err.Error()
		sum := sha256.Sum256([]byte(res.Stderr))
		res.StderrSHA256 = hex.EncodeToString(sum[:])
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	f, err := os.Open(path)
	if err != nil {
		return fail(err)
	}
	defer f.Close()

	out, hash, truncated, err := captureLimited(f, maxBytes)
	if err != nil {
		return fail(err)
	}
	res.Status, res.ExitCode = "SUCCEEDED", 0
	res.Stdout, res.StdoutSHA256, res.StdoutTruncated = out, hash, truncated
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func captureLimited(r io.Reader, maxBytes int) (text string, hashHex string, truncated bool, err error) {
	if maxBytes <= 0 {
		maxBytes = 1
	}
	h := sha256.New()
	var buf bytes.Buffer
	tmp := make([]byte, 32*1024)
	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			_, _ = h.Write(tmp[:n])
			remain := maxBytes - buf.Len()
			if remain > 0 {
				if n <= remain {
					_, _ = buf.Write(tmp[:n])
				} else {
					_, _ = buf.Write(tmp[:remain])
					truncated = true
				}
			} else {
				truncated = true
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return "", "", false, rerr
		}
	}
	return buf.String(), hex.EncodeToString(h.Sum(nil)), truncated, nil
}
