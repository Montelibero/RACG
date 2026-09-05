package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/configedit"
)

// SetConfig executes an already-authorized configuration edit, including its backup policy.
func SetConfig(in configedit.ConfigSet) Result {
	start := time.Now()
	res, err := configedit.Set(in)
	if err != nil {
		return fileEditResult(start, "", err)
	}
	return fileEditResult(start, formatConfigSetResult(res), nil)
}

func fileEditResult(start time.Time, output string, err error) Result {
	res := Result{Status: "SUCCEEDED", ExitCode: 0, Stdout: output}
	if err != nil {
		res.Status, res.ExitCode = "FAILED", -1
		res.Stdout, res.Stderr = "", err.Error()
	}
	outHash, errHash := sha256.Sum256([]byte(res.Stdout)), sha256.Sum256([]byte(res.Stderr))
	res.StdoutSHA256, res.StderrSHA256 = hex.EncodeToString(outHash[:]), hex.EncodeToString(errHash[:])
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func formatConfigSetResult(res configedit.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "path: %s\n", res.Path)
	fmt.Fprintf(&b, "format: %s\n", res.Format)
	fmt.Fprintf(&b, "key: %s\n", res.Key)
	if res.Created {
		fmt.Fprintln(&b, "created: true")
	} else {
		fmt.Fprintln(&b, "created: false")
	}
	fmt.Fprintf(&b, "file_created: %t\n", res.FileCreated)
	fmt.Fprintf(&b, "old: %s\n", res.OldValue)
	fmt.Fprintf(&b, "new: %s\n", res.NewValue)
	if res.BackupPath != "" {
		fmt.Fprintf(&b, "backup_path: %s\n", res.BackupPath)
	}
	return strings.TrimRight(b.String(), "\n")
}
