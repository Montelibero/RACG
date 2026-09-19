package authority

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

// CreateDeviceTransfer lets an already enrolled phone authorize another
// independently generated phone. It does not copy private keys and does not
// revoke the authorizing phone.
func (a *Authority) CreateDeviceTransfer(ctx context.Context, grant approval.SignedDeviceTransferGrant) error {
	now := a.now().UTC()
	var currentKey []byte
	var keyType string
	var revoked int
	err := a.db.QueryRowContext(ctx,
		"SELECT public_key,key_type,revoked FROM authority_devices WHERE device_id=?",
		grant.Grant.CurrentDeviceID,
	).Scan(&currentKey, &keyType, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("authorizing device is not enrolled")
	}
	if err != nil {
		return err
	}
	if revoked != 0 {
		return errors.New("authorizing device revoked")
	}
	if err := approval.VerifyDeviceTransferGrant(grant, a.serverID, grant.Grant.CurrentDeviceID, keyType, currentKey, now); err != nil {
		return err
	}
	tokenHash := cloneBytes(grant.Grant.TransferTokenSHA256)
	encodedGrant, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	var existing string
	err = a.db.QueryRowContext(ctx,
		"SELECT new_device_id FROM authority_device_transfers WHERE transfer_hash=?",
		tokenHash,
	).Scan(&existing)
	if err == nil {
		return errors.New("transfer token already used")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = a.db.ExecContext(ctx,
		"INSERT INTO authority_device_transfers(transfer_hash,current_device_id,new_device_id,grant,expires_at) VALUES(?,?,?,?,?)",
		tokenHash,
		grant.Grant.CurrentDeviceID,
		grant.Grant.NewDeviceID,
		encodedGrant,
		grant.Grant.ValidUntil,
	)
	return err
}

// EnrollTransfer consumes a transfer token and registers the new phone's own
// approval and poll public keys.
func (a *Authority) EnrollTransfer(ctx context.Context, submission approval.DeviceTransferSubmission) (approval.SignedDeviceTransferReceipt, error) {
	now := a.now().UTC()
	newEnrollment := submission.Enrollment.Enrollment
	if len(submission.Token) == 0 {
		return approval.SignedDeviceTransferReceipt{}, errors.New("transfer token required")
	}
	if err := approval.VerifyDeviceTransferEnrollment(submission.Enrollment, a.serverID, newEnrollment.NewDeviceID, now); err != nil {
		return approval.SignedDeviceTransferReceipt{}, err
	}
	tokenHash := sha256.Sum256(submission.Token)

	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return approval.SignedDeviceTransferReceipt{}, err
	}
	defer tx.Rollback()

	var storedCurrentID, expiresAt string
	var grantBlob []byte
	var usedAt sql.NullString
	err = tx.QueryRowContext(ctx,
		"SELECT current_device_id,expires_at,used_at,grant FROM authority_device_transfers WHERE transfer_hash=? AND new_device_id=?",
		tokenHash[:], newEnrollment.NewDeviceID,
	).Scan(&storedCurrentID, &expiresAt, &usedAt, &grantBlob)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.SignedDeviceTransferReceipt{}, errors.New("invalid transfer token")
	}
	if err != nil {
		return approval.SignedDeviceTransferReceipt{}, err
	}
	if usedAt.Valid {
		return approval.SignedDeviceTransferReceipt{}, errors.New("transfer token already used")
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return approval.SignedDeviceTransferReceipt{}, fmt.Errorf("stored transfer expiry: %w", err)
	}
	if !now.Before(expires) {
		return approval.SignedDeviceTransferReceipt{}, errors.New("transfer token expired")
	}

	var currentKey []byte
	var currentKeyType string
	var currentRevoked int
	if err := tx.QueryRowContext(ctx,
		"SELECT public_key,key_type,revoked FROM authority_devices WHERE device_id=?",
		storedCurrentID,
	).Scan(&currentKey, &currentKeyType, &currentRevoked); err != nil {
		return approval.SignedDeviceTransferReceipt{}, fmt.Errorf("authorizing device lookup: %w", err)
	}
	if currentRevoked != 0 {
		return approval.SignedDeviceTransferReceipt{}, errors.New("authorizing device revoked")
	}
	var storedGrant approval.SignedDeviceTransferGrant
	if err := json.Unmarshal(grantBlob, &storedGrant); err != nil {
		return approval.SignedDeviceTransferReceipt{}, fmt.Errorf("decode stored transfer grant: %w", err)
	}
	if err := approval.VerifyDeviceTransferGrant(storedGrant, a.serverID, storedCurrentID, currentKeyType, currentKey, now); err != nil {
		return approval.SignedDeviceTransferReceipt{}, err
	}

	var existing string
	err = tx.QueryRowContext(ctx,
		"SELECT device_id FROM authority_devices WHERE device_id=?",
		newEnrollment.NewDeviceID,
	).Scan(&existing)
	if err == nil {
		return approval.SignedDeviceTransferReceipt{}, errors.New("transfer target already enrolled")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return approval.SignedDeviceTransferReceipt{}, err
	}

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO authority_devices(device_id,public_key,revoked,key_type,poll_public_key) VALUES(?,?,0,?,?)",
		newEnrollment.NewDeviceID,
		newEnrollment.PublicKey,
		newEnrollment.KeyType,
		newEnrollment.PollKey,
	); err != nil {
		return approval.SignedDeviceTransferReceipt{}, err
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE authority_device_transfers SET used_at=? WHERE transfer_hash=? AND used_at IS NULL",
		now.Format(time.RFC3339Nano), tokenHash[:],
	)
	if err != nil {
		return approval.SignedDeviceTransferReceipt{}, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return approval.SignedDeviceTransferReceipt{}, errors.New("transfer token already used")
	}
	if err := tx.Commit(); err != nil {
		return approval.SignedDeviceTransferReceipt{}, err
	}
	return approval.SignDeviceTransferReceipt(storedGrant, currentKey, submission.Enrollment, now, a.key)
}

func cloneBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	return append([]byte(nil), data...)
}
