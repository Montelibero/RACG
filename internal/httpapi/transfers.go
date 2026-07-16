package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/rules"
)

type stagedUpload struct {
	UploadID  string `json:"upload_id"`
	SessionID string `json:"session_id"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	CreatedAt string `json:"created_at"`
}

type downloadArtifact struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Name   string `json:"name"`
}

func (a *API) transferDir() string {
	if strings.HasPrefix(a.cfg.DBPath, "file:") || strings.TrimSpace(a.cfg.DBPath) == "" {
		return filepath.Join(os.TempDir(), "racg-transfers")
	}
	return a.cfg.DBPath + ".transfers"
}

func (a *API) maxTransferBytes() int64 {
	if a.cfg.MaxTransferBytes > 0 {
		return a.cfg.MaxTransferBytes
	}
	return 100 * 1024 * 1024
}

func (a *API) uploadDataPath(id string) string {
	return filepath.Join(a.transferDir(), "upload-"+id+".bin")
}

func (a *API) uploadMetaPath(id string) string {
	return filepath.Join(a.transferDir(), "upload-"+id+".json")
}

func (a *API) downloadDataPath(requestID string) string {
	return filepath.Join(a.transferDir(), "download-"+requestID+".bin")
}

func (a *API) downloadMetaPath(requestID string) string {
	return filepath.Join(a.transferDir(), "download-"+requestID+".json")
}

func (a *API) handleUploadStage(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if err := os.MkdirAll(a.transferDir(), 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	a.cleanupExpiredTransfers(24 * time.Hour)

	id := uuid.NewString()
	tmp, err := os.CreateTemp(a.transferDir(), ".racg-upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	_ = tmp.Chmod(0o600)

	h := sha256.New()
	limited := io.LimitReader(r.Body, a.maxTransferBytes()+1)
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), limited)
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil {
		if copyErr == nil {
			copyErr = closeErr
		}
		writeError(w, http.StatusBadRequest, "UPLOAD_FAILED", copyErr.Error(), "")
		return
	}
	if n > a.maxTransferBytes() {
		writeError(w, http.StatusRequestEntityTooLarge, "TRANSFER_TOO_LARGE", fmt.Sprintf("maximum transfer size is %d bytes", a.maxTransferBytes()), "")
		return
	}
	if err := os.Rename(tmpPath, a.uploadDataPath(id)); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	meta := stagedUpload{
		UploadID: id, SessionID: c.SessionID, Size: n,
		SHA256: hex.EncodeToString(h.Sum(nil)), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSONFileAtomic(a.uploadMetaPath(id), meta, 0o600); err != nil {
		_ = os.Remove(a.uploadDataPath(id))
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"upload_id":  meta.UploadID,
		"size":       meta.Size,
		"sha256":     meta.SHA256,
		"created_at": meta.CreatedAt,
	})
}

func (a *API) cleanupUploadForOp(op rules.Op) {
	if op.Type != "fs.upload" {
		return
	}
	var p struct {
		UploadID string `json:"upload_id"`
	}
	if json.Unmarshal(op.Payload, &p) != nil || !validTransferID(p.UploadID) {
		return
	}
	_ = os.Remove(a.uploadDataPath(p.UploadID))
	_ = os.Remove(a.uploadMetaPath(p.UploadID))
}

func (a *API) cleanupExpiredTransfers(maxAge time.Duration) {
	entries, err := os.ReadDir(a.transferDir())
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasPrefix(entry.Name(), "upload-") && !strings.HasPrefix(entry.Name(), "download-")) {
			continue
		}
		info, err := entry.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(a.transferDir(), entry.Name()))
		}
	}
}

func (a *API) prepareTransferOp(c auth.Claims, op *rules.Op) error {
	switch op.Type {
	case "fs.upload":
		var p struct {
			Path     string `json:"path"`
			UploadID string `json:"upload_id"`
			Mode     string `json:"mode,omitempty"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return fmt.Errorf("invalid fs.upload payload: %w", err)
		}
		if strings.TrimSpace(p.Path) == "" || !validTransferID(p.UploadID) {
			return errors.New("fs.upload requires path and valid upload_id")
		}
		if p.Mode != "" {
			if _, err := parseFileMode(p.Mode); err != nil {
				return err
			}
		}
		meta, err := a.loadStagedUpload(p.UploadID)
		if err != nil {
			return fmt.Errorf("staged upload not found: %w", err)
		}
		if meta.SessionID != c.SessionID {
			return errors.New("staged upload belongs to another session")
		}
		op.Payload = mustJSON(map[string]any{
			"path": p.Path, "upload_id": p.UploadID, "size": meta.Size,
			"sha256": meta.SHA256, "mode": p.Mode,
		})
	case "fs.download":
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil || strings.TrimSpace(p.Path) == "" {
			return errors.New("fs.download requires path")
		}
	}
	return nil
}

func (a *API) loadStagedUpload(id string) (stagedUpload, error) {
	var meta stagedUpload
	b, err := os.ReadFile(a.uploadMetaPath(id))
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return meta, err
	}
	return meta, nil
}

func (a *API) executeFileUpload(startedAt time.Time, c auth.Claims, op rules.Op) *resultRecord {
	var p struct {
		Path     string `json:"path"`
		UploadID string `json:"upload_id"`
		Size     int64  `json:"size"`
		SHA256   string `json:"sha256"`
		Mode     string `json:"mode"`
	}
	if err := json.Unmarshal(op.Payload, &p); err != nil {
		return transferErrorResult(startedAt, err)
	}
	meta, err := a.loadStagedUpload(p.UploadID)
	if err != nil {
		return transferErrorResult(startedAt, fmt.Errorf("load staged upload: %w", err))
	}
	if meta.SessionID != c.SessionID || meta.Size != p.Size || meta.SHA256 != p.SHA256 {
		return transferErrorResult(startedAt, errors.New("staged upload metadata mismatch"))
	}

	mode := os.FileMode(0o644)
	var uid, gid = -1, -1
	if info, statErr := os.Stat(p.Path); statErr == nil {
		if !info.Mode().IsRegular() {
			return transferErrorResult(startedAt, errors.New("upload target is not a regular file"))
		}
		mode = info.Mode().Perm()
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return transferErrorResult(startedAt, statErr)
	}
	if p.Mode != "" {
		mode, err = parseFileMode(p.Mode)
		if err != nil {
			return transferErrorResult(startedAt, err)
		}
	}

	src, err := os.Open(a.uploadDataPath(p.UploadID))
	if err != nil {
		return transferErrorResult(startedAt, err)
	}
	defer src.Close()
	dir := filepath.Dir(p.Path)
	tmp, err := os.CreateTemp(dir, ".racg-upload-*")
	if err != nil {
		return transferErrorResult(startedAt, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return transferErrorResult(startedAt, err)
	}
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			_ = tmp.Close()
			return transferErrorResult(startedAt, err)
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
		return transferErrorResult(startedAt, copyErr)
	}
	gotHash := hex.EncodeToString(h.Sum(nil))
	if n != p.Size || gotHash != p.SHA256 {
		return transferErrorResult(startedAt, errors.New("staged upload checksum mismatch"))
	}
	if err := os.Rename(tmpPath, p.Path); err != nil {
		return transferErrorResult(startedAt, err)
	}
	_ = os.Remove(a.uploadDataPath(p.UploadID))
	_ = os.Remove(a.uploadMetaPath(p.UploadID))
	return transferSuccessResult(startedAt, fmt.Sprintf("uploaded %d bytes\nsha256: %s", n, gotHash))
}

func (a *API) executeFileDownload(startedAt time.Time, requestID string, op rules.Op) *resultRecord {
	a.cleanupExpiredTransfers(24 * time.Hour)
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(op.Payload, &p); err != nil {
		return transferErrorResult(startedAt, err)
	}
	src, err := os.Open(p.Path)
	if err != nil {
		return transferErrorResult(startedAt, err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return transferErrorResult(startedAt, err)
	}
	if !info.Mode().IsRegular() {
		return transferErrorResult(startedAt, errors.New("download source is not a regular file"))
	}
	if info.Size() > a.maxTransferBytes() {
		return transferErrorResult(startedAt, fmt.Errorf("file exceeds maximum transfer size of %d bytes", a.maxTransferBytes()))
	}
	if err := os.MkdirAll(a.transferDir(), 0o700); err != nil {
		return transferErrorResult(startedAt, err)
	}
	tmp, err := os.CreateTemp(a.transferDir(), ".racg-download-*")
	if err != nil {
		return transferErrorResult(startedAt, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	_ = tmp.Chmod(0o600)
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, a.maxTransferBytes()+1))
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	if closeErr := tmp.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return transferErrorResult(startedAt, copyErr)
	}
	if n > a.maxTransferBytes() {
		return transferErrorResult(startedAt, fmt.Errorf("file exceeds maximum transfer size of %d bytes", a.maxTransferBytes()))
	}
	if err := os.Rename(tmpPath, a.downloadDataPath(requestID)); err != nil {
		return transferErrorResult(startedAt, err)
	}
	meta := downloadArtifact{Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: fmt.Sprintf("%04o", info.Mode().Perm()), Name: filepath.Base(p.Path)}
	if err := writeJSONFileAtomic(a.downloadMetaPath(requestID), meta, 0o600); err != nil {
		_ = os.Remove(a.downloadDataPath(requestID))
		return transferErrorResult(startedAt, err)
	}
	return transferSuccessResult(startedAt, fmt.Sprintf("download ready: %d bytes\nsha256: %s", n, meta.SHA256))
}

func (a *API) handleRequestFile(w http.ResponseWriter, r *http.Request, c auth.Claims, requestID string) {
	a.reqsMu.Lock()
	rec, ok := a.reqs[requestID]
	a.reqsMu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", "request not found", requestID)
		return
	}
	if rec.SessionID != c.SessionID {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "download belongs to another session", requestID)
		return
	}
	var op rules.Op
	_ = json.Unmarshal(rec.Op, &op)
	if rec.Status != "SUCCEEDED" || op.Type != "fs.download" {
		writeError(w, http.StatusConflict, "DOWNLOAD_NOT_READY", "approved download is not ready", requestID)
		return
	}
	var meta downloadArtifact
	b, err := os.ReadFile(a.downloadMetaPath(requestID))
	if err != nil || json.Unmarshal(b, &meta) != nil {
		writeError(w, http.StatusNotFound, "DOWNLOAD_NOT_FOUND", "download artifact not found", requestID)
		return
	}
	f, err := os.Open(a.downloadDataPath(requestID))
	if err != nil {
		writeError(w, http.StatusNotFound, "DOWNLOAD_NOT_FOUND", err.Error(), requestID)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": meta.Name}))
	w.Header().Set("X-RACG-SHA256", meta.SHA256)
	w.Header().Set("X-RACG-Mode", meta.Mode)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func parseFileMode(s string) (os.FileMode, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 8, 9)
	if err != nil || n > 0o777 {
		return 0, fmt.Errorf("invalid file mode %q; use octal permissions such as 0644", s)
	}
	return os.FileMode(n), nil
}

func validTransferID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

func writeJSONFileAtomic(path string, value any, mode os.FileMode) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".racg-meta-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func transferSuccessResult(startedAt time.Time, stdout string) *resultRecord {
	finishedAt := time.Now().UTC()
	return &resultRecord{
		StartedAt: startedAt.Format(time.RFC3339Nano), FinishedAt: finishedAt.Format(time.RFC3339Nano),
		DurationMs: finishedAt.Sub(startedAt).Milliseconds(), ExitCode: 0, Status: "SUCCEEDED",
		Stdout: stdout, StdoutSHA256: sha256Hex([]byte(stdout)), StderrSHA256: sha256Hex(nil),
	}
}

func transferErrorResult(startedAt time.Time, err error) *resultRecord {
	finishedAt := time.Now().UTC()
	msg := err.Error()
	return &resultRecord{
		StartedAt: startedAt.Format(time.RFC3339Nano), FinishedAt: finishedAt.Format(time.RFC3339Nano),
		DurationMs: finishedAt.Sub(startedAt).Milliseconds(), ExitCode: -1, Status: "FAILED",
		Stderr: msg, StdoutSHA256: sha256Hex(nil), StderrSHA256: sha256Hex([]byte(msg)),
	}
}
