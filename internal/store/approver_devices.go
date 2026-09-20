package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ApproverDevice is one enrolled remote approver client (phone, desktop, ...).
// Private keys never leave the device; only the public keys are stored here.
// PublicKey signs decisions (biometry-bound on phones); PollPublicKey, when
// present, signs pending-list reads and carries no user-auth requirement.
type ApproverDevice struct {
	DeviceID      string
	PublicKey     []byte
	PollPublicKey []byte
	CreatedAt     time.Time
	Enabled       bool
	DisabledAt    *time.Time
}

// UpsertApproverDevice enrolls or re-enrolls a device. Re-pairing an existing
// device ID replaces its key and re-enables it; pairing requires a one-time
// enrollment token, so this stays a trusted administrative act. A nil
// pollPublicKey keeps any previously stored poll key (legacy single-key
// devices poll with their approval key).
func (s *Store) UpsertApproverDevice(ctx context.Context, deviceID string, publicKey, pollPublicKey []byte, createdAt time.Time) error {
	if strings.TrimSpace(deviceID) == "" {
		return fmt.Errorf("device ID required")
	}
	if len(publicKey) == 0 {
		return fmt.Errorf("public key required")
	}
	var pollArg any
	if len(pollPublicKey) > 0 {
		pollArg = pollPublicKey
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO approver_devices (device_id, public_key, poll_public_key, created_at, enabled)
		VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(device_id) DO UPDATE SET
		  public_key = excluded.public_key,
		  poll_public_key = COALESCE(excluded.poll_public_key, approver_devices.poll_public_key),
		  enabled = 1,
		  disabled_at = NULL`,
		deviceID, publicKey, pollArg, createdAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetApproverDevice(ctx context.Context, deviceID string) (ApproverDevice, bool, error) {
	if strings.TrimSpace(deviceID) == "" {
		return ApproverDevice{}, false, fmt.Errorf("device ID required")
	}
	var (
		dev        ApproverDevice
		created    string
		disabled   sql.NullString
		enabledInt int
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT device_id, public_key, poll_public_key, created_at, enabled, disabled_at
		  FROM approver_devices
		 WHERE device_id = ?`, deviceID).
		Scan(&dev.DeviceID, &dev.PublicKey, &dev.PollPublicKey, &created, &enabledInt, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ApproverDevice{}, false, nil
	}
	if err != nil {
		return ApproverDevice{}, false, err
	}
	dev.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return ApproverDevice{}, false, fmt.Errorf("parse device created_at: %w", err)
	}
	dev.Enabled = enabledInt != 0
	if disabled.Valid && strings.TrimSpace(disabled.String) != "" {
		at, err := time.Parse(time.RFC3339Nano, disabled.String)
		if err != nil {
			return ApproverDevice{}, false, fmt.Errorf("parse device disabled_at: %w", err)
		}
		dev.DisabledAt = &at
	}
	return dev, true, nil
}

// SetApproverDeviceEnabled revokes (enabled=false) or re-enables a device.
// Revoked devices fail poll and decision signature checks immediately.
func (s *Store) SetApproverDeviceEnabled(ctx context.Context, deviceID string, enabled bool, at time.Time) error {
	if strings.TrimSpace(deviceID) == "" {
		return fmt.Errorf("device ID required")
	}
	var disabledAt any
	if !enabled {
		disabledAt = at.UTC().Format(time.RFC3339Nano)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE approver_devices SET enabled = ?, disabled_at = COALESCE(?, disabled_at) WHERE device_id = ?`,
		boolToInt(enabled), disabledAt, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("unknown approver device: %s", deviceID)
	}
	return nil
}

func (s *Store) ListApproverDevices(ctx context.Context, limit int) ([]ApproverDevice, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT device_id, public_key, poll_public_key, created_at, enabled, disabled_at
		  FROM approver_devices
		 ORDER BY created_at DESC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ApproverDevice
	for rows.Next() {
		var (
			dev        ApproverDevice
			created    string
			disabled   sql.NullString
			enabledInt int
		)
		if err := rows.Scan(&dev.DeviceID, &dev.PublicKey, &dev.PollPublicKey, &created, &enabledInt, &disabled); err != nil {
			return nil, err
		}
		dev.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, fmt.Errorf("parse device created_at: %w", err)
		}
		dev.Enabled = enabledInt != 0
		if disabled.Valid && strings.TrimSpace(disabled.String) != "" {
			at, err := time.Parse(time.RFC3339Nano, disabled.String)
			if err != nil {
				return nil, fmt.Errorf("parse device disabled_at: %w", err)
			}
			dev.DisabledAt = &at
		}
		out = append(out, dev)
	}
	return out, rows.Err()
}
