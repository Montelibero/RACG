package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type UploadSpec struct {
	Path   string
	Size   int64
	SHA256 string
	Mode   string
}

type FileArtifact struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Name   string `json:"name"`
}

// UploadFile installs already-authorized bytes only after checking their size and digest.
func UploadFile(p UploadSpec, src io.Reader) Result {
	startedAt := time.Now()
	var err error
	mode := os.FileMode(0o644)
	var uid, gid = -1, -1
	if info, statErr := os.Stat(p.Path); statErr == nil {
		if !info.Mode().IsRegular() {
			return fileEditResult(startedAt, "", errors.New("upload target is not a regular file"))
		}
		mode = info.Mode().Perm()
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fileEditResult(startedAt, "", statErr)
	}
	if p.Mode != "" {
		mode, err = ParseFileMode(p.Mode)
		if err != nil {
			return fileEditResult(startedAt, "", err)
		}
	}

	dir := filepath.Dir(p.Path)
	tmp, err := os.CreateTemp(dir, ".racg-upload-*")
	if err != nil {
		return fileEditResult(startedAt, "", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fileEditResult(startedAt, "", err)
	}
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			_ = tmp.Close()
			return fileEditResult(startedAt, "", err)
		}
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), src)
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	if closeErr := tmp.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return fileEditResult(startedAt, "", copyErr)
	}
	gotHash := hex.EncodeToString(h.Sum(nil))
	if n != p.Size || gotHash != p.SHA256 {
		return fileEditResult(startedAt, "", errors.New("staged upload checksum mismatch"))
	}
	if err := os.Rename(tmpPath, p.Path); err != nil {
		return fileEditResult(startedAt, "", err)
	}
	return fileEditResult(startedAt, fmt.Sprintf("uploaded %d bytes\nsha256: %s", n, gotHash), nil)
}

// DownloadFile snapshots an already-authorized regular file into private artifact storage.
func DownloadFile(path, artifactPath string, maxBytes int64) (FileArtifact, Result) {
	startedAt := time.Now()
	src, err := os.Open(path)
	if err != nil {
		return FileArtifact{}, fileEditResult(startedAt, "", err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return FileArtifact{}, fileEditResult(startedAt, "", err)
	}
	if !info.Mode().IsRegular() {
		return FileArtifact{}, fileEditResult(startedAt, "", errors.New("download source is not a regular file"))
	}
	if info.Size() > maxBytes {
		return FileArtifact{}, fileEditResult(startedAt, "", fmt.Errorf("file exceeds maximum transfer size of %d bytes", maxBytes))
	}
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o700); err != nil {
		return FileArtifact{}, fileEditResult(startedAt, "", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(artifactPath), ".racg-download-*")
	if err != nil {
		return FileArtifact{}, fileEditResult(startedAt, "", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	_ = tmp.Chmod(0o600)
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, maxBytes+1))
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	if closeErr := tmp.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return FileArtifact{}, fileEditResult(startedAt, "", copyErr)
	}
	if n > maxBytes {
		return FileArtifact{}, fileEditResult(startedAt, "", fmt.Errorf("file exceeds maximum transfer size of %d bytes", maxBytes))
	}
	if err := os.Rename(tmpPath, artifactPath); err != nil {
		return FileArtifact{}, fileEditResult(startedAt, "", err)
	}
	meta := FileArtifact{Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: fmt.Sprintf("%04o", info.Mode().Perm()), Name: filepath.Base(path)}
	return meta, fileEditResult(startedAt, fmt.Sprintf("download ready: %d bytes\nsha256: %s", n, meta.SHA256), nil)
}

// ParseFileMode preserves the transfer protocol\'s octal permission syntax.
func ParseFileMode(s string) (os.FileMode, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 8, 9)
	if err != nil || n > 0o777 {
		return 0, fmt.Errorf("invalid file mode %q; use octal permissions such as 0644", s)
	}
	return os.FileMode(n), nil
}
