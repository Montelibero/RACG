package approval

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// DeviceTransferGrant authorizes a new, independently generated mobile key
// pair. The old private keys never leave the old phone.
type DeviceTransferGrant struct {
	Version             int    `json:"version"`
	ServerID            string `json:"server_id"`
	CurrentDeviceID     string `json:"current_device_id"`
	KeyType             string `json:"key_type"`
	NewDeviceID         string `json:"new_device_id"`
	TransferTokenSHA256 []byte `json:"transfer_token_sha256"`
	Challenge           []byte `json:"challenge"`
	ValidUntil          string `json:"valid_until"`
}

type SignedDeviceTransferGrant struct {
	Grant     DeviceTransferGrant `json:"grant"`
	Signature []byte              `json:"signature"`
}

type DeviceTransferEnrollment struct {
	Version             int    `json:"version"`
	ServerID            string `json:"server_id"`
	NewDeviceID         string `json:"new_device_id"`
	KeyType             string `json:"key_type"`
	PublicKey           []byte `json:"public_key"`
	PollKey             []byte `json:"poll_public_key"`
	GrantChallenge      []byte `json:"grant_challenge"`
	TransferTokenSHA256 []byte `json:"transfer_token_sha256"`
	Challenge           []byte `json:"challenge"`
	ValidUntil          string `json:"valid_until"`
}

type SignedDeviceTransferEnrollment struct {
	Enrollment DeviceTransferEnrollment `json:"enrollment"`
	Signature  []byte                   `json:"signature"`
}

type DeviceTransferSubmission struct {
	Enrollment SignedDeviceTransferEnrollment `json:"enrollment"`
	Token      []byte                         `json:"token"`
}

type DeviceTransferReceipt struct {
	Version         int    `json:"version"`
	ServerID        string `json:"server_id"`
	CurrentDeviceID string `json:"current_device_id"`
	NewDeviceID     string `json:"new_device_id"`
	KeyType         string `json:"key_type"`
	PublicKey       []byte `json:"public_key"`
	PollKey         []byte `json:"poll_public_key"`
	GrantSHA256     string `json:"grant_sha256"`
	Challenge       []byte `json:"challenge"`
	Status          string `json:"status"`
}

type SignedDeviceTransferReceipt struct {
	Receipt   DeviceTransferReceipt `json:"receipt"`
	Signature []byte                `json:"signature"`
}

func NewDeviceTransferGrant(serverID, currentDeviceID, keyType, newDeviceID string, token []byte, validUntil time.Time) (DeviceTransferGrant, error) {
	grant := DeviceTransferGrant{
		Version:             Version,
		ServerID:            serverID,
		CurrentDeviceID:     currentDeviceID,
		KeyType:             keyType,
		NewDeviceID:         newDeviceID,
		TransferTokenSHA256: tokenDigest(token),
		Challenge:           make([]byte, 32),
		ValidUntil:          validUntil.UTC().Format(time.RFC3339Nano),
	}
	if _, err := readRandom(grant.Challenge); err != nil {
		return DeviceTransferGrant{}, err
	}
	if err := validateDeviceTransferGrant(grant); err != nil {
		return DeviceTransferGrant{}, err
	}
	return grant, nil
}

func SignDeviceTransferGrant(grant DeviceTransferGrant, keyType string, key crypto.Signer) (SignedDeviceTransferGrant, error) {
	if err := validateDeviceTransferGrant(grant); err != nil {
		return SignedDeviceTransferGrant{}, err
	}
	if err := validateDeviceSigner(keyType, key, grant.CurrentDeviceID); err != nil {
		return SignedDeviceTransferGrant{}, err
	}
	data, err := message("device-transfer-grant", grant)
	if err != nil {
		return SignedDeviceTransferGrant{}, err
	}
	signature, err := SignWithDeviceKey(keyType, key, data)
	if err != nil {
		return SignedDeviceTransferGrant{}, err
	}
	return SignedDeviceTransferGrant{Grant: grant, Signature: signature}, nil
}

func VerifyDeviceTransferGrant(signed SignedDeviceTransferGrant, serverID, currentDeviceID, keyType string, publicKey []byte, now time.Time) error {
	grant := signed.Grant
	if err := validateDeviceTransferGrant(grant); err != nil {
		return err
	}
	if grant.ServerID != serverID || grant.CurrentDeviceID != currentDeviceID {
		return errors.New("device transfer grant identity mismatch")
	}
	data, err := message("device-transfer-grant", grant)
	if err != nil {
		return err
	}
	if err := VerifyDeviceKeySignature(keyType, publicKey, data, signed.Signature); err != nil {
		return err
	}
	return checkFutureTime(grant.ValidUntil, now)
}

func NewDeviceTransferEnrollment(serverID, newDeviceID, keyType string, publicKey, pollKey []byte, grantChallenge, token []byte, validUntil time.Time) (DeviceTransferEnrollment, error) {
	enrollment := DeviceTransferEnrollment{
		Version:             Version,
		ServerID:            serverID,
		NewDeviceID:         newDeviceID,
		KeyType:             keyType,
		PublicKey:           cloneBytes(publicKey),
		PollKey:             cloneBytes(pollKey),
		GrantChallenge:      cloneBytes(grantChallenge),
		TransferTokenSHA256: tokenDigest(token),
		Challenge:           make([]byte, 32),
		ValidUntil:          validUntil.UTC().Format(time.RFC3339Nano),
	}
	if _, err := readRandom(enrollment.Challenge); err != nil {
		return DeviceTransferEnrollment{}, err
	}
	if err := validateDeviceTransferEnrollment(enrollment); err != nil {
		return DeviceTransferEnrollment{}, err
	}
	return enrollment, nil
}

func SignDeviceTransferEnrollment(enrollment DeviceTransferEnrollment, key crypto.Signer) (SignedDeviceTransferEnrollment, error) {
	if err := validateDeviceTransferEnrollment(enrollment); err != nil {
		return SignedDeviceTransferEnrollment{}, err
	}
	if err := validateDeviceSigner(enrollment.KeyType, key, enrollment.NewDeviceID); err != nil {
		return SignedDeviceTransferEnrollment{}, err
	}
	data, err := message("device-transfer-enrollment", enrollment)
	if err != nil {
		return SignedDeviceTransferEnrollment{}, err
	}
	signature, err := SignWithDeviceKey(enrollment.KeyType, key, data)
	if err != nil {
		return SignedDeviceTransferEnrollment{}, err
	}
	return SignedDeviceTransferEnrollment{Enrollment: enrollment, Signature: signature}, nil
}

func VerifyDeviceTransferEnrollment(signed SignedDeviceTransferEnrollment, serverID, newDeviceID string, now time.Time) error {
	enrollment := signed.Enrollment
	if err := validateDeviceTransferEnrollment(enrollment); err != nil {
		return err
	}
	if enrollment.ServerID != serverID || enrollment.NewDeviceID != newDeviceID {
		return errors.New("device transfer enrollment identity mismatch")
	}
	data, err := message("device-transfer-enrollment", enrollment)
	if err != nil {
		return err
	}
	if err := VerifyDeviceKeySignature(enrollment.KeyType, enrollment.PublicKey, data, signed.Signature); err != nil {
		return err
	}
	return checkFutureTime(enrollment.ValidUntil, now)
}

func SignDeviceTransferReceipt(grant SignedDeviceTransferGrant, currentKey []byte, enrollment SignedDeviceTransferEnrollment, now time.Time, authorityKey ed25519.PrivateKey) (SignedDeviceTransferReceipt, error) {
	if len(authorityKey) != ed25519.PrivateKeySize {
		return SignedDeviceTransferReceipt{}, errors.New("invalid authority signing key")
	}
	if err := VerifyDeviceTransferGrant(grant, grant.Grant.ServerID, grant.Grant.CurrentDeviceID, grant.Grant.KeyType, currentKey, now); err != nil {
		return SignedDeviceTransferReceipt{}, err
	}
	if err := VerifyDeviceTransferEnrollment(enrollment, enrollment.Enrollment.ServerID, enrollment.Enrollment.NewDeviceID, now); err != nil {
		return SignedDeviceTransferReceipt{}, err
	}
	if grant.Grant.TransferTokenSHA256 == nil || !bytes.Equal(grant.Grant.TransferTokenSHA256, enrollment.Enrollment.TransferTokenSHA256) || !bytes.Equal(grant.Grant.Challenge, enrollment.Enrollment.GrantChallenge) {
		return SignedDeviceTransferReceipt{}, errors.New("device transfer enrollment does not match grant")
	}
	digest, err := deviceTransferGrantDigest(grant.Grant)
	if err != nil {
		return SignedDeviceTransferReceipt{}, err
	}
	receipt := DeviceTransferReceipt{
		Version:         Version,
		ServerID:        enrollment.Enrollment.ServerID,
		CurrentDeviceID: grant.Grant.CurrentDeviceID,
		NewDeviceID:     enrollment.Enrollment.NewDeviceID,
		KeyType:         enrollment.Enrollment.KeyType,
		PublicKey:       cloneBytes(enrollment.Enrollment.PublicKey),
		PollKey:         cloneBytes(enrollment.Enrollment.PollKey),
		GrantSHA256:     digest,
		Challenge:       cloneBytes(enrollment.Enrollment.Challenge),
		Status:          "TRANSFERRED",
	}
	// Authority signatures are Ed25519; this protocol does not make the
	// authority key switchable.
	data, err := message("device-transfer-receipt", receipt)
	if err != nil {
		return SignedDeviceTransferReceipt{}, err
	}
	signature := ed25519.Sign(authorityKey, data)
	return SignedDeviceTransferReceipt{Receipt: receipt, Signature: signature}, nil
}

func VerifyDeviceTransferReceipt(grant SignedDeviceTransferGrant, currentKey []byte, enrollment SignedDeviceTransferEnrollment, signedReceipt SignedDeviceTransferReceipt, authorityKey ed25519.PublicKey, now time.Time) error {
	if err := VerifyDeviceTransferGrant(grant, grant.Grant.ServerID, grant.Grant.CurrentDeviceID, grant.Grant.KeyType, currentKey, now); err != nil {
		return err
	}
	if err := VerifyDeviceTransferEnrollment(enrollment, enrollment.Enrollment.ServerID, enrollment.Enrollment.NewDeviceID, now); err != nil {
		return err
	}
	digest, err := deviceTransferGrantDigest(grant.Grant)
	if err != nil {
		return err
	}
	receipt := signedReceipt.Receipt
	switch {
	case receipt.Version != Version:
		err = errors.New("unsupported transfer receipt version")
	case receipt.ServerID != grant.Grant.ServerID:
		err = errors.New("transfer receipt server mismatch")
	case receipt.CurrentDeviceID != grant.Grant.CurrentDeviceID || receipt.NewDeviceID != grant.Grant.NewDeviceID:
		err = errors.New("transfer receipt identity mismatch")
	case receipt.KeyType != enrollment.Enrollment.KeyType ||
		!bytes.Equal(receipt.PublicKey, enrollment.Enrollment.PublicKey) ||
		!bytes.Equal(receipt.PollKey, enrollment.Enrollment.PollKey):
		err = errors.New("transfer receipt key mismatch")
	case receipt.GrantSHA256 != digest:
		err = errors.New("transfer receipt grant mismatch")
	case !bytes.Equal(receipt.Challenge, enrollment.Enrollment.Challenge):
		err = errors.New("transfer receipt challenge mismatch")
	case receipt.Status != "TRANSFERRED":
		err = errors.New("transfer receipt status mismatch")
	}
	if err != nil {
		return err
	}
	data, err := message("device-transfer-receipt", receipt)
	if err != nil {
		return err
	}
	if !ed25519Verify(authorityKey, data, signedReceipt.Signature) {
		return errors.New("invalid transfer receipt signature")
	}
	return nil
}

func validateDeviceTransferGrant(grant DeviceTransferGrant) error {
	switch {
	case grant.Version != Version:
		return errors.New("unsupported device transfer grant version")
	case grant.ServerID == "" || grant.CurrentDeviceID == "" || grant.NewDeviceID == "":
		return errors.New("invalid device transfer grant identity")
	case ValidateDeviceKeyType(grant.KeyType) != nil:
		return ValidateDeviceKeyType(grant.KeyType)
	case grant.CurrentDeviceID == grant.NewDeviceID:
		return errors.New("transfer target equals current device")
	case len(grant.TransferTokenSHA256) != sha256.Size:
		return errors.New("invalid transfer token digest")
	case len(grant.Challenge) != 32:
		return errors.New("invalid transfer grant challenge")
	}
	return nil
}

func validateDeviceTransferEnrollment(enrollment DeviceTransferEnrollment) error {
	switch {
	case enrollment.Version != Version:
		return errors.New("unsupported transfer enrollment version")
	case enrollment.ServerID == "" || enrollment.NewDeviceID == "":
		return errors.New("invalid transfer enrollment identity")
	case ValidateDeviceKeyType(enrollment.KeyType) != nil:
		return ValidateDeviceKeyType(enrollment.KeyType)
	case len(enrollment.PublicKey) == 0:
		return errors.New("invalid transfer approval key")
	case validateECDSAP256PublicKey(enrollment.PollKey) != nil:
		return fmt.Errorf("invalid transfer poll key: %w", validateECDSAP256PublicKey(enrollment.PollKey))
	case len(enrollment.GrantChallenge) != 32:
		return errors.New("invalid transfer grant challenge")
	case len(enrollment.TransferTokenSHA256) != sha256.Size:
		return errors.New("invalid transfer token digest")
	case len(enrollment.Challenge) != 32:
		return errors.New("invalid transfer enrollment challenge")
	}
	return nil
}

func deviceTransferGrantDigest(grant DeviceTransferGrant) (string, error) {
	if err := validateDeviceTransferGrant(grant); err != nil {
		return "", err
	}
	data, err := message("device-transfer-grant", grant)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
