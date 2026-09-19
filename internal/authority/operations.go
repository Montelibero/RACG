package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/configedit"
	"github.com/itolstov/racg/internal/executor"
)

// OperationExecutionOptions reuses the existing interactive executor defaults.
// Zero MaxOutputBytes/KillGrace values are normalized by executor.New. A zero
// DefaultTimeout uses the established 120-second default. These are deployment
// settings, not approval semantics.
type OperationExecutionOptions struct {
	Executor       executor.Options
	DefaultTimeout time.Duration
}

func (o OperationExecutionOptions) normalized() OperationExecutionOptions {
	if o.Executor.MaxOutputBytes <= 0 {
		o.Executor.MaxOutputBytes = 1024 * 1024
	}
	if o.Executor.KillGrace <= 0 {
		o.Executor.KillGrace = 3 * time.Second
	}
	if o.DefaultTimeout <= 0 {
		o.DefaultTimeout = 120 * time.Second
	}
	return o
}

// ExecuteStored claims the authorized request and dispatches its exact stored
// operation to the existing executor implementations. It never accepts bytes
// or paths from the broker, and never reruns a claimed request.
func (a *Authority) ExecuteStored(ctx context.Context, id string, options OperationExecutionOptions) (executor.Result, error) {
	return a.Execute(ctx, id, func(ctx context.Context, request approval.Request) executor.Result {
		return a.runStoredOperation(ctx, request, options.normalized())
	})
}

func (a *Authority) runStoredOperation(ctx context.Context, request approval.Request, options OperationExecutionOptions) executor.Result {
	var envelope struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := strictUnmarshal(request.Operation, &envelope); err != nil {
		return failedOperationResult(fmt.Errorf("outer operation: %w", err))
	}
	switch envelope.Type {
	case "cmd.run":
		return a.runCommandOperation(ctx, request, envelope.Payload, options)
	case "fs.read":
		var payload readFilePayload
		if err := strictUnmarshal(envelope.Payload, &payload); err != nil {
			return failedOperationResult(fmt.Errorf("fs.read payload: %w", err))
		}
		maxBytes := payload.MaxBytes
		if maxBytes <= 0 || maxBytes > int64(options.Executor.MaxOutputBytes) {
			maxBytes = int64(options.Executor.MaxOutputBytes)
		}
		return executor.ReadFile(payload.Path, int(maxBytes))
	case "fs.patch_unified":
		var payload patchFilePayload
		if err := strictUnmarshal(envelope.Payload, &payload); err != nil {
			return failedOperationResult(fmt.Errorf("patch payload: %w", err))
		}
		return executor.PatchFile(payload.Path, payload.Diff)
	case "fs.upload":
		return a.runUploadOperation(ctx, request, envelope.Payload)
	case "fs.download":
		return a.runDownloadOperation(ctx, request.RequestID, envelope.Payload, options)
	case "conf.set":
		var payload configSetPayload
		if err := strictUnmarshal(envelope.Payload, &payload); err != nil {
			return failedOperationResult(fmt.Errorf("config payload: %w", err))
		}
		backup := true
		if payload.Backup != nil {
			backup = *payload.Backup
		}
		return executor.SetConfig(configedit.ConfigSet{
			Path:      payload.Path,
			Format:    payload.Format,
			Key:       payload.Key,
			Value:     payload.Value,
			ValueType: payload.ValueType,
			Backup:    backup,
			BackupDir: payload.BackupDir,
			Create:    payload.Create,
		})
	default:
		return failedOperationResult(fmt.Errorf("unsupported stored operation %q", envelope.Type))
	}
}

func (a *Authority) runCommandOperation(ctx context.Context, request approval.Request, payloadBytes json.RawMessage, options OperationExecutionOptions) executor.Result {
	var payload cmdRunPayload
	if err := strictUnmarshal(payloadBytes, &payload); err != nil {
		return failedOperationResult(fmt.Errorf("command payload: %w", err))
	}
	var stdin io.Reader
	if payload.StdinUploadID != "" {
		data, err := a.StagedUploadForRequest(ctx, request, payload.StdinUploadID)
		if err != nil {
			return failedOperationResult(fmt.Errorf("command staged input: %w", err))
		}
		stdin = bytes.NewReader(data)
	}
	timeout := time.Duration(payload.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = options.DefaultTimeout
	}
	result := executor.New(options.Executor).Run(ctx, executor.Spec{
		Argv:    payload.Argv,
		Cwd:     payload.Cwd,
		Stdin:   stdin,
		Timeout: timeout,
	})
	if payload.StdinUploadID != "" {
		_ = a.deleteStagedUploadForRequest(request, payload.StdinUploadID)
	}
	return result
}

func (a *Authority) runUploadOperation(ctx context.Context, request approval.Request, payloadBytes json.RawMessage) executor.Result {
	var payload uploadFilePayload
	if err := strictUnmarshal(payloadBytes, &payload); err != nil {
		return failedOperationResult(err)
	}
	data, err := a.StagedUploadForRequest(context.WithoutCancel(ctx), request, payload.UploadID)
	if err != nil {
		return failedOperationResult(err)
	}
	result := executor.UploadFile(executor.UploadSpec{
		Path:   payload.Path,
		Size:   payload.Size,
		SHA256: payload.SHA256,
		Mode:   payload.Mode,
	}, bytes.NewReader(data))
	if result.Status == "SUCCEEDED" {
		_ = a.deleteStagedUploadForRequest(request, payload.UploadID)
	}
	return result
}

func (a *Authority) runDownloadOperation(ctx context.Context, requestID string, payloadBytes json.RawMessage, options OperationExecutionOptions) executor.Result {
	options = options.normalized()
	var payload downloadFilePayload
	if err := strictUnmarshal(payloadBytes, &payload); err != nil {
		return failedOperationResult(err)
	}
	directory, err := os.MkdirTemp("", "racg-authority-download-")
	if err != nil {
		return failedOperationResult(err)
	}
	artifactPath := filepath.Join(directory, "snapshot.bin")
	defer os.RemoveAll(directory)
	meta, result := executor.DownloadFile(payload.Path, artifactPath)
	if result.Status != "SUCCEEDED" {
		return result
	}
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return failedOperationResult(err)
	}
	if err := a.storeDownloadArtifact(context.WithoutCancel(ctx), requestID, meta, data); err != nil {
		return failedOperationResult(fmt.Errorf("store download artifact: %w", err))
	}
	return result
}

func failedOperationResult(err error) executor.Result {
	message := err.Error()
	stdoutHash := sha256.Sum256(nil)
	stderrHash := sha256.Sum256([]byte(message))
	return executor.Result{
		Status:       "FAILED",
		ExitCode:     -1,
		Stderr:       message,
		StdoutSHA256: hex.EncodeToString(stdoutHash[:]),
		StderrSHA256: hex.EncodeToString(stderrHash[:]),
	}
}

func (a *Authority) deleteStagedUploadForRequest(request approval.Request, uploadID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.db.Exec("DELETE FROM authority_staged_uploads WHERE upload_id=? AND claimed_request_id=? AND client_id=?", uploadID, request.RequestID, request.ClientID)
	return err
}

type StoredDownloadArtifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Data   []byte `json:"-"`
}

func (a *Authority) storeDownloadArtifact(ctx context.Context, requestID string, record executor.FileArtifact, data []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.db.ExecContext(ctx,
		"INSERT INTO authority_download_artifacts(request_id,name,size,sha256,mode,data) VALUES(?,?,?,?,?,?)",
		requestID, record.Name, record.Size, record.SHA256, record.Mode, data)
	return err
}

// DownloadArtifact returns an authority-owned snapshot only to the trusted
// agent-result transport after the owning request reached terminal success.
func (a *Authority) DownloadArtifact(ctx context.Context, request approval.Request) (StoredDownloadArtifact, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var artifact StoredDownloadArtifact
	var status string
	err := a.db.QueryRowContext(ctx,
		"SELECT r.status,a.name,a.size,a.sha256,a.mode,a.data FROM authority_download_artifacts a JOIN authority_requests r ON r.request_id=a.request_id WHERE a.request_id=?",
		request.RequestID).Scan(&status, &artifact.Name, &artifact.Size, &artifact.SHA256, &artifact.Mode, &artifact.Data)
	if err != nil {
		return StoredDownloadArtifact{}, err
	}
	if status != "SUCCEEDED" {
		return StoredDownloadArtifact{}, errors.New("download artifact request is not successful")
	}
	if artifact.Size != int64(len(artifact.Data)) || artifact.SHA256 != approval.SHA256Hex(artifact.Data) {
		return StoredDownloadArtifact{}, errors.New("download artifact integrity mismatch")
	}
	return artifact, nil
}
