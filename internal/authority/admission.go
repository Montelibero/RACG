package authority

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/executor"
)

type stagedUploadRef struct {
	uploadID string
}

type cmdRunPayload struct {
	Argv          []string `json:"argv"`
	Cwd           string   `json:"cwd,omitempty"`
	TimeoutSec    int      `json:"timeout_sec,omitempty"`
	StdinUploadID string   `json:"stdin_upload_id,omitempty"`
	StdinSize     int64    `json:"stdin_size,omitempty"`
	StdinSHA256   string   `json:"stdin_sha256,omitempty"`
}

type readFilePayload struct {
	Path     string `json:"path"`
	MaxBytes int64  `json:"max_bytes,omitempty"`
}

type patchFilePayload struct {
	Path string `json:"path"`
	Diff string `json:"diff"`
}

type uploadFilePayload struct {
	Path     string `json:"path"`
	UploadID string `json:"upload_id"`
	Size     int64  `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Mode     string `json:"mode,omitempty"`
}

type downloadFilePayload struct {
	Path string `json:"path"`
}

type configSetPayload struct {
	Path      string `json:"path"`
	Format    string `json:"format"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	ValueType string `json:"value_type,omitempty"`
	Backup    *bool  `json:"backup,omitempty"`
	BackupDir string `json:"backup_dir,omitempty"`
	Create    bool   `json:"create,omitempty"`
}

func strictUnmarshal(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

// admitOperation validates a service operation and binds staged-byte metadata
// before the authority freezes the exact operation bytes.
func (a *Authority) admitOperation(tx *sql.Tx, clientID string, operation []byte) ([]byte, []stagedUploadRef, error) {
	var envelope struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := strictUnmarshal(operation, &envelope); err != nil {
		return nil, nil, fmt.Errorf("invalid operation: %w", err)
	}
	var payload any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil || payload == nil {
		return nil, nil, errors.New("operation payload must be a JSON object")
	}
	if _, ok := payload.(map[string]any); !ok {
		return nil, nil, errors.New("operation payload must be a JSON object")
	}
	var refs []stagedUploadRef
	var err error
	switch envelope.Type {
	case "cmd.run":
		var operationPayload cmdRunPayload
		if err = strictUnmarshal(envelope.Payload, &operationPayload); err == nil {
			err = validateCmdRun(&operationPayload)
		}
		if err == nil && operationPayload.StdinUploadID != "" {
			var size int64
			var digest string
			size, digest, err = a.claimableStagedUpload(tx, clientID, operationPayload.StdinUploadID)
			if err == nil {
				operationPayload.StdinSize = size
				operationPayload.StdinSHA256 = digest
				envelope.Payload, err = json.Marshal(operationPayload)
				refs = append(refs, stagedUploadRef{uploadID: operationPayload.StdinUploadID})
			}
		}
	case "fs.read":
		var operationPayload readFilePayload
		if err = strictUnmarshal(envelope.Payload, &operationPayload); err == nil {
			err = validateReadFile(&operationPayload)
		}
	case "fs.patch_unified":
		var operationPayload patchFilePayload
		if err = strictUnmarshal(envelope.Payload, &operationPayload); err == nil {
			err = validatePatchFile(&operationPayload)
		}
	case "fs.upload":
		var operationPayload uploadFilePayload
		if err = strictUnmarshal(envelope.Payload, &operationPayload); err == nil {
			err = validateUploadFile(&operationPayload)
		}
		if err == nil {
			var size int64
			var digest string
			size, digest, err = a.claimableStagedUpload(tx, clientID, operationPayload.UploadID)
			if err == nil {
				operationPayload.Size = size
				operationPayload.SHA256 = digest
				envelope.Payload, err = json.Marshal(operationPayload)
				refs = append(refs, stagedUploadRef{uploadID: operationPayload.UploadID})
			}
		}
	case "fs.download":
		var operationPayload downloadFilePayload
		if err = strictUnmarshal(envelope.Payload, &operationPayload); err == nil {
			err = validateDownloadFile(&operationPayload)
		}
	case "conf.set":
		var operationPayload configSetPayload
		if err = strictUnmarshal(envelope.Payload, &operationPayload); err == nil {
			err = validateConfigSet(&operationPayload)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported operation type %q", envelope.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("invalid %s operation: %w", envelope.Type, err)
	}
	admitted, err := json.Marshal(envelope)
	if err != nil {
		return nil, nil, err
	}
	return admitted, refs, nil
}

func validateCmdRun(payload *cmdRunPayload) error {
	if len(payload.Argv) == 0 || payload.Argv[0] == "" {
		return errors.New("argv with a non-empty program required")
	}
	if payload.TimeoutSec < 0 {
		return errors.New("timeout_sec must not be negative")
	}
	if payload.StdinUploadID == "" {
		if payload.StdinSize != 0 || payload.StdinSHA256 != "" {
			return errors.New("stdin metadata requires stdin_upload_id")
		}
		return nil
	}
	if !validStagedUploadID(payload.StdinUploadID) {
		return errors.New("invalid stdin_upload_id")
	}
	if payload.StdinSize != 0 || payload.StdinSHA256 != "" {
		return errors.New("stdin size and digest are assigned by authority admission")
	}
	return nil
}

func validateReadFile(payload *readFilePayload) error {
	if payload.Path == "" {
		return errors.New("path required")
	}
	if payload.MaxBytes < 0 {
		return errors.New("max_bytes must not be negative")
	}
	return nil
}

func validatePatchFile(payload *patchFilePayload) error {
	if payload.Path == "" || payload.Diff == "" {
		return errors.New("path and diff required")
	}
	return nil
}

func validateUploadFile(payload *uploadFilePayload) error {
	if payload.Path == "" || payload.UploadID == "" {
		return errors.New("path and upload_id required")
	}
	if !validStagedUploadID(payload.UploadID) {
		return errors.New("invalid upload_id")
	}
	if payload.Size != 0 || payload.SHA256 != "" {
		return errors.New("size and sha256 are assigned by authority admission")
	}
	if payload.Mode != "" {
		if _, err := executor.ParseFileMode(payload.Mode); err != nil {
			return err
		}
	}
	return nil
}

func validateDownloadFile(payload *downloadFilePayload) error {
	if payload.Path == "" {
		return errors.New("path required")
	}
	return nil
}

func validateConfigSet(payload *configSetPayload) error {
	if payload.Path == "" || payload.Format == "" || payload.Key == "" {
		return errors.New("path, format and key required")
	}
	switch payload.ValueType {
	case "", "string", "bool", "int", "float", "null", "json":
	default:
		return fmt.Errorf("unsupported value_type %q", payload.ValueType)
	}
	return nil
}

func validStagedUploadID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (a *Authority) claimableStagedUpload(tx *sql.Tx, clientID, uploadID string) (int64, string, error) {
	var size int64
	var digest string
	err := tx.QueryRowContext(context.Background(),
		"SELECT size,sha256 FROM authority_staged_uploads WHERE client_id=? AND upload_id=? AND claimed_request_id IS NULL AND valid_until>?",
		clientID, uploadID, a.now().UTC().Format(time.RFC3339Nano)).Scan(&size, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", errors.New("staged upload is not available")
	}
	return size, digest, err
}

func claimStagedUploads(tx *sql.Tx, clientID, requestID string, refs []stagedUploadRef) error {
	for _, ref := range refs {
		result, err := tx.ExecContext(context.Background(),
			"UPDATE authority_staged_uploads SET claimed_request_id=? WHERE client_id=? AND upload_id=? AND claimed_request_id IS NULL",
			requestID, clientID, ref.uploadID)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return errors.New("staged upload was claimed concurrently")
		}
	}
	return nil
}

// StageUpload stores agent-authenticated bytes in authority-owned SQLite. The
// signed metadata authorizes storage only; it never authorizes use against a
// target. Bytes become usable only through operation admission.
func (a *Authority) StageUpload(ctx context.Context, signed approval.SignedStagedUpload, data []byte) (approval.StagedUpload, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.StagedUpload{}, err
	}
	defer tx.Rollback()
	upload := signed.Upload
	var key []byte
	var revoked int
	if err := tx.QueryRowContext(ctx, "SELECT public_key,revoked FROM authority_agents WHERE client_id=?", upload.ClientID).Scan(&key, &revoked); err != nil {
		return approval.StagedUpload{}, fmt.Errorf("agent is not enrolled: %w", err)
	}
	if revoked != 0 {
		return approval.StagedUpload{}, errors.New("agent revoked")
	}
	if err := approval.VerifyStagedUpload(signed, a.serverID, upload.ClientID, key, data, a.now().UTC()); err != nil {
		return approval.StagedUpload{}, err
	}
	var existingSize int64
	var existingDigest string
	err = tx.QueryRowContext(ctx, "SELECT size,sha256 FROM authority_staged_uploads WHERE client_id=? AND upload_id=?", upload.ClientID, upload.UploadID).Scan(&existingSize, &existingDigest)
	if err == nil {
		if existingSize != upload.Size || existingDigest != upload.SHA256 {
			return approval.StagedUpload{}, errors.New("staged upload ID reused for different bytes")
		}
		return upload, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return approval.StagedUpload{}, err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO authority_staged_uploads(client_id,upload_id,size,sha256,data,valid_until) VALUES(?,?,?,?,?,?)",
		upload.ClientID, upload.UploadID, upload.Size, upload.SHA256, data, upload.ValidUntil); err != nil {
		return approval.StagedUpload{}, err
	}
	return upload, tx.Commit()
}

// StagedUploadForRequest returns authority-stored bytes only after execution
// authorization has claimed them for this exact signed request.
func (a *Authority) StagedUploadForRequest(ctx context.Context, request approval.Request, uploadID string) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var data []byte
	var size int64
	var digest, clientID string
	err := a.db.QueryRowContext(ctx,
		"SELECT data,size,sha256,client_id FROM authority_staged_uploads WHERE upload_id=? AND claimed_request_id=?",
		uploadID, request.RequestID).Scan(&data, &size, &digest, &clientID)
	if err != nil {
		return nil, fmt.Errorf("staged upload is not bound to request: %w", err)
	}
	if clientID != request.ClientID || size != int64(len(data)) || digest != approval.SHA256Hex(data) {
		return nil, errors.New("staged upload metadata mismatch")
	}
	return append([]byte(nil), data...), nil
}
