// Package authority stores service-mode approval state independently of the
// interactive server. It is not a broker API or an execution backend.
package authority

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/itolstov/racg/internal/approval"
)

// Authority requires an exclusively owned database in authority-owned storage.
// The composition root must enforce ownership, file/socket permissions and
// single-process lifetime. Never give the broker this handle or signing key.
type Authority struct {
	mu       sync.Mutex
	db       *sql.DB
	serverID string
	key      ed25519.PrivateKey
	now      func() time.Time
}

// New initializes a separate service database. No interactive audit or unsigned
// rule import is performed. The caller retains database lifecycle ownership.
func New(ctx context.Context, db *sql.DB, serverID string, key ed25519.PrivateKey, now func() time.Time) (*Authority, error) {
	if db == nil || serverID == "" || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("authority database, server identity and signing key required")
	}
	if now == nil {
		now = time.Now
	}
	a := &Authority{db: db, serverID: serverID, key: append(ed25519.PrivateKey(nil), key...), now: now}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, statement := range []string{
		"CREATE TABLE IF NOT EXISTS authority_identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), server_id TEXT NOT NULL, public_key BLOB NOT NULL)",
		"CREATE TABLE IF NOT EXISTS authority_devices (device_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
		"CREATE TABLE IF NOT EXISTS authority_agents (client_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
		"CREATE TABLE IF NOT EXISTS authority_submissions (client_id TEXT NOT NULL, nonce BLOB NOT NULL, digest BLOB NOT NULL, request_id TEXT NOT NULL UNIQUE, PRIMARY KEY(client_id,nonce))",
		"CREATE TABLE IF NOT EXISTS authority_requests (request_id TEXT PRIMARY KEY, envelope BLOB NOT NULL, status TEXT NOT NULL, signed_decision BLOB, consumed_at TEXT)",
		"CREATE TABLE IF NOT EXISTS authority_executions (request_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, result BLOB)",
		"CREATE TABLE IF NOT EXISTS authority_staged_uploads (client_id TEXT NOT NULL, upload_id TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, data BLOB NOT NULL, valid_until TEXT NOT NULL, claimed_request_id TEXT, PRIMARY KEY(client_id,upload_id))",
		"CREATE TABLE IF NOT EXISTS authority_download_artifacts (request_id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, mode TEXT NOT NULL, data BLOB NOT NULL)",
		"CREATE TABLE IF NOT EXISTS authority_grants (grant_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, client_id TEXT NOT NULL, canonical_scope BLOB NOT NULL, rule BLOB NOT NULL, expires_at TEXT, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS authority_grant_requests (request_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS authority_cancellations (request_id TEXT PRIMARY KEY, nonce BLOB NOT NULL, cancellation BLOB NOT NULL)",
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return nil, err
		}
	}
	pub := a.key.Public().(ed25519.PublicKey)
	if _, err := tx.ExecContext(ctx, "INSERT INTO authority_identity(singleton,server_id,public_key) VALUES(1,?,?) ON CONFLICT(singleton) DO NOTHING", serverID, []byte(pub)); err != nil {
		return nil, err
	}
	var storedID string
	var storedKey []byte
	if err := tx.QueryRowContext(ctx, "SELECT server_id, public_key FROM authority_identity WHERE singleton=1").Scan(&storedID, &storedKey); err != nil {
		return nil, err
	}
	if storedID != serverID || !pub.Equal(ed25519.PublicKey(storedKey)) {
		return nil, errors.New("authority database belongs to a different server identity")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return a, nil
}

// EnrollTrusted is an administrative operation for a trusted local/SSH path.
// It must not be exposed to the broker or authenticated by an agent token.
// Re-enrollment is explicit trusted key rotation; pending signatures from the
// old key no longer verify.
func (a *Authority) EnrollTrusted(ctx context.Context, deviceID string, key ed25519.PublicKey) error {
	if deviceID == "" || len(key) != ed25519.PublicKeySize {
		return errors.New("device identity and Ed25519 public key required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.db.ExecContext(ctx, "INSERT INTO authority_devices(device_id,public_key,revoked) VALUES(?,?,0) ON CONFLICT(device_id) DO UPDATE SET public_key=excluded.public_key, revoked=0", deviceID, []byte(key))
	return err
}

func (a *Authority) RevokeTrusted(ctx context.Context, deviceID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	result, err := a.db.ExecContext(ctx, "UPDATE authority_devices SET revoked=1 WHERE device_id=?", deviceID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

// FreezeTrusted creates an immutable authority-generated request ID/challenge.
// The caller must already authenticate client/session identity, validate the
// operation and freeze any staged content in authority-owned storage. JSON
// syntax alone does not make an operation safe or its referenced files immutable.
func (a *Authority) FreezeTrusted(ctx context.Context, clientID, sessionID string, operation []byte) (approval.SignedRequest, error) {
	request, err := approval.NewRequest(a.serverID, uuid.NewString(), clientID, sessionID, operation)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	signed, err := approval.SignRequest(request, a.key)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return approval.SignedRequest{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.ExecContext(ctx, "INSERT INTO authority_requests(request_id,envelope,status) VALUES(?,?,'PENDING_APPROVAL')", request.RequestID, data); err != nil {
		return approval.SignedRequest{}, err
	}
	return signed, nil
}

func (a *Authority) Request(ctx context.Context, id string) (approval.SignedRequest, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var data []byte
	var status string
	if err := a.db.QueryRowContext(ctx, "SELECT envelope,status FROM authority_requests WHERE request_id=?", id).Scan(&data, &status); err != nil {
		return approval.SignedRequest{}, "", err
	}
	var signed approval.SignedRequest
	if err := json.Unmarshal(data, &signed); err != nil {
		return approval.SignedRequest{}, "", err
	}
	if err := approval.VerifyRequest(signed, a.serverID, a.key.Public().(ed25519.PublicKey)); err != nil {
		return approval.SignedRequest{}, "", err
	}
	return signed, status, nil
}

// PublicKey returns the pinned authority identity for trusted local clients.
func (a *Authority) PublicKey() ed25519.PublicKey {
	if a == nil {
		return nil
	}
	return a.key.Public().(ed25519.PublicKey)
}

// SubmitDecision is the local composition boundary for a transport adapter;
// it is not a network listener. It durably consumes the first valid decision
// and returns an authority-signed receipt. A returned receipt means the
// decision was stored, not that execution started or completed.
func (a *Authority) SubmitDecision(ctx context.Context, id string, decision approval.SignedDecision, challenge []byte) (approval.SignedDecisionReceipt, error) {
	if len(challenge) != 32 {
		return approval.SignedDecisionReceipt{}, errors.New("invalid decision receipt challenge")
	}
	request, err := a.Consume(ctx, id, decision)
	if err != nil {
		return approval.SignedDecisionReceipt{}, err
	}
	return approval.SignDecisionReceipt(request, decision, challenge, a.key)
}

// Consume verifies an enrolled, currently non-revoked device against the
// authority's stored bytes, then durably consumes that request. Only the first
// single-shot decision succeeds, including across restarts.
//
// Returned bytes are the stored operation, never broker display text. This is
// not an execution API: composition must dispatch only a successful ALLOW_ONCE,
// never rerun a consumed request after a crash and report uncertain execution.
// Reusable grants are intentionally not wired until their authoritative
// scope/lifetime enforcement is implemented.
func (a *Authority) Consume(ctx context.Context, id string, decision approval.SignedDecision) (approval.Request, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch decision.Decision.Action {
	case "DENY", "ALLOW_ONCE", "ALLOW_UNTIL", "ALLOW_ALWAYS":
	default:
		return approval.Request{}, errors.New("unsupported service authority decision")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.Request{}, err
	}
	defer tx.Rollback()
	var data []byte
	var status string
	if err := tx.QueryRowContext(ctx, "SELECT envelope,status FROM authority_requests WHERE request_id=?", id).Scan(&data, &status); err != nil {
		return approval.Request{}, err
	}
	if status != "PENDING_APPROVAL" {
		return approval.Request{}, errors.New("request decision already consumed")
	}
	var request approval.SignedRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return approval.Request{}, err
	}
	if err := approval.VerifyRequest(request, a.serverID, a.key.Public().(ed25519.PublicKey)); err != nil {
		return approval.Request{}, err
	}
	if request.Request.RequestID != id {
		return approval.Request{}, errors.New("stored request identity mismatch")
	}
	var key []byte
	var revoked int
	if err := tx.QueryRowContext(ctx, "SELECT public_key,revoked FROM authority_devices WHERE device_id=?", decision.Decision.DeviceID).Scan(&key, &revoked); err != nil {
		return approval.Request{}, fmt.Errorf("device is not enrolled: %w", err)
	}
	if revoked != 0 {
		return approval.Request{}, errors.New("device revoked")
	}
	now := a.now().UTC()
	if err := approval.VerifyDecision(request.Request, decision, decision.Decision.DeviceID, ed25519.PublicKey(key), now); err != nil {
		return approval.Request{}, err
	}
	encoded, err := json.Marshal(decision)
	if err != nil {
		return approval.Request{}, err
	}
	status = "AUTHORIZED"
	if decision.Decision.Action == "DENY" {
		status = "DENIED"
	} else if decision.Decision.Action != "ALLOW_ONCE" {
		if _, err := a.createGrantTx(ctx, tx, decision.Decision.DeviceID, request.Request, decision); err != nil {
			return approval.Request{}, err
		}
	}
	result, err := tx.ExecContext(ctx, "UPDATE authority_requests SET status=?,signed_decision=?,consumed_at=? WHERE request_id=? AND status='PENDING_APPROVAL'", status, encoded, now.Format(time.RFC3339Nano), id)
	if err != nil {
		return approval.Request{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return approval.Request{}, err
	}
	if n != 1 {
		return approval.Request{}, errors.New("request decision already consumed")
	}
	if err := tx.Commit(); err != nil {
		return approval.Request{}, err
	}
	return request.Request, nil
}
