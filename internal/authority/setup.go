package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

// CreateDeviceSetupTrusted issues one opaque token over the trusted admin
// socket. Only its digest is persisted; possession plus a signature by the
// newly generated device key is required to enroll through the broker.
func (a *Authority) CreateDeviceSetupTrusted(ctx context.Context, deviceID string, validity time.Duration) ([]byte, time.Time, error) {
	if deviceID == "" {
		return nil, time.Time{}, errors.New("device setup identity required")
	}
	if validity <= 0 {
		return nil, time.Time{}, errors.New("device setup validity must be positive")
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, time.Time{}, fmt.Errorf("generate device setup token: %w", err)
	}
	now := a.now().UTC()
	expiresAt := now.Add(validity)
	tokenHash := sha256.Sum256(token)

	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer tx.Rollback()
	var existing string
	if err := tx.QueryRowContext(ctx, "SELECT device_id FROM authority_devices WHERE device_id=?", deviceID).Scan(&existing); err == nil {
		return nil, time.Time{}, errors.New("device is already enrolled; use explicit rotation")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO authority_device_setups(token_hash,device_id,expires_at) VALUES(?,?,?)",
		tokenHash[:], deviceID, expiresAt.Format(time.RFC3339Nano),
	); err != nil {
		return nil, time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return nil, time.Time{}, err
	}
	return token, expiresAt, nil
}

// EnrollDevice consumes a single setup token. The broker can relay it, but
// cannot invent authority identity, choose a different device ID, or enroll
// without a signature from the submitted new public key.
func (a *Authority) EnrollDevice(ctx context.Context, submission approval.DeviceEnrollmentSubmission) (approval.SignedDeviceEnrollmentReceipt, error) {
	now := a.now().UTC()
	if submission.Enrollment.Enrollment.KeyType != approval.KeyTypeECDSAP256 {
		return approval.SignedDeviceEnrollmentReceipt{}, errors.New("mobile setup requires an ECDSA P-256 device key")
	}
	if err := approval.VerifyDeviceEnrollment(submission.Enrollment, a.serverID, now); err != nil {
		return approval.SignedDeviceEnrollmentReceipt{}, err
	}
	if len(submission.Token) == 0 {
		return approval.SignedDeviceEnrollmentReceipt{}, errors.New("device setup token required")
	}
	tokenHash := sha256.Sum256(submission.Token)

	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.SignedDeviceEnrollmentReceipt{}, err
	}
	defer tx.Rollback()

	var storedDeviceID, expiresAt string
	var usedAt sql.NullString
	err = tx.QueryRowContext(ctx,
		"SELECT device_id,expires_at,used_at FROM authority_device_setups WHERE token_hash=?",
		tokenHash[:],
	).Scan(&storedDeviceID, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.SignedDeviceEnrollmentReceipt{}, errors.New("invalid device setup token")
	}
	if err != nil {
		return approval.SignedDeviceEnrollmentReceipt{}, err
	}
	if usedAt.Valid {
		return approval.SignedDeviceEnrollmentReceipt{}, errors.New("device setup token already used")
	}
	if storedDeviceID != submission.Enrollment.Enrollment.DeviceID {
		return approval.SignedDeviceEnrollmentReceipt{}, errors.New("device setup identity mismatch")
	}
	parsedExpiresAt, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return approval.SignedDeviceEnrollmentReceipt{}, fmt.Errorf("stored device setup expiry: %w", err)
	}
	if !now.Before(parsedExpiresAt) {
		return approval.SignedDeviceEnrollmentReceipt{}, errors.New("device setup token expired")
	}

	var existing string
	if err := tx.QueryRowContext(ctx,
		"SELECT device_id FROM authority_devices WHERE device_id=?",
		storedDeviceID,
	).Scan(&existing); err == nil {
		return approval.SignedDeviceEnrollmentReceipt{}, errors.New("device is already enrolled")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return approval.SignedDeviceEnrollmentReceipt{}, err
	}

	publicKey := ed25519.PublicKey(submission.Enrollment.Enrollment.PublicKey)
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO authority_devices(device_id,public_key,revoked,key_type) VALUES(?,?,0,?)",
		storedDeviceID, []byte(publicKey), submission.Enrollment.Enrollment.KeyType,
	); err != nil {
		return approval.SignedDeviceEnrollmentReceipt{}, err
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE authority_device_setups SET used_at=?,enrolled_public_key=? WHERE token_hash=? AND used_at IS NULL",
		now.Format(time.RFC3339Nano), []byte(publicKey), tokenHash[:],
	)
	if err != nil {
		return approval.SignedDeviceEnrollmentReceipt{}, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return approval.SignedDeviceEnrollmentReceipt{}, errors.New("device setup token already used")
	}
	if err := tx.Commit(); err != nil {
		return approval.SignedDeviceEnrollmentReceipt{}, err
	}
	return approval.SignDeviceEnrollmentReceipt(submission.Enrollment, now, a.key)
}
