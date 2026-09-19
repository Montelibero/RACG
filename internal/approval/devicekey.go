package approval

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	KeyTypeEd25519   = "ed25519"
	KeyTypeECDSAP256 = "ecdsa-p256"
)

type asn1ECDSASignature struct {
	R *big.Int
	S *big.Int
}

func ValidateDeviceKeyType(keyType string) error {
	switch keyType {
	case KeyTypeEd25519, KeyTypeECDSAP256:
		return nil
	default:
		return fmt.Errorf("unsupported device key type %q", keyType)
	}
}

func readRandom(data []byte) (int, error) {
	return rand.Read(data)
}

func cloneBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	return append([]byte(nil), data...)
}

func checkFutureTime(encoded string, now time.Time) error {
	until, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil {
		return fmt.Errorf("parse validity: %w", err)
	}
	if !now.Before(until) {
		return errors.New("validity expired")
	}
	return nil
}

func validateDeviceSigner(keyType string, key crypto.Signer, deviceID string) error {
	switch keyType {
	case KeyTypeEd25519:
		private, ok := key.(ed25519.PrivateKey)
		if !ok || len(private) != ed25519.PrivateKeySize {
			return errors.New("device signer is not Ed25519")
		}
		if deviceID == "" {
			return errors.New("invalid Ed25519 device signer")
		}
		return nil
	case KeyTypeECDSAP256:
		private, ok := key.(*ecdsa.PrivateKey)
		if !ok || private.Curve != elliptic.P256() || deviceID == "" {
			return errors.New("device signer is not ECDSA P-256")
		}
		return nil
	default:
		return fmt.Errorf("unsupported device signer type %q", keyType)
	}
}

func ed25519Sign(private ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(private, message)
}

func ed25519Verify(public ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(public, message, signature)
}

func validateECDSAP256PublicKey(encoded []byte) error {
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return errors.New("public key is not ECDSA P-256")
	}
	return nil
}

func mustECDSAP256PublicKey(encoded []byte) *ecdsa.PublicKey {
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		panic(fmt.Sprintf("validated public key failed to decode: %v", err))
	}
	return parsed.(*ecdsa.PublicKey)
}

// VerifyDeviceKeySignature verifies a signature over the exact canonical bytes.
// ECDSA P-256 keys use PKIX/SPKI public-key encoding and ASN.1 DER signatures,
// matching Android Keystore's SHA256withECDSA output.
func VerifyDeviceKeySignature(keyType string, publicKey, message, signature []byte) error {
	if err := ValidateDeviceKeyType(keyType); err != nil {
		return err
	}
	switch keyType {
	case KeyTypeEd25519:
		if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
			return errors.New("invalid device signature")
		}
		return nil
	case KeyTypeECDSAP256:
		if err := validateECDSAP256PublicKey(publicKey); err != nil {
			return fmt.Errorf("invalid ECDSA device key: %w", err)
		}
		public := mustECDSAP256PublicKey(publicKey)
		var raw asn1ECDSASignature
		if rest, err := asn1.Unmarshal(signature, &raw); err != nil || len(rest) != 0 || raw.R == nil || raw.S == nil {
			return errors.New("invalid ECDSA device signature")
		}
		hash := crypto.SHA256.New()
		hash.Write(message)
		if !ecdsa.Verify(public, hash.Sum(nil), raw.R, raw.S) {
			return errors.New("invalid device signature")
		}
		return nil
	default:
		return errors.New("unsupported device key type")
	}
}

func SignWithDeviceKey(keyType string, key crypto.Signer, message []byte) ([]byte, error) {
	if err := ValidateDeviceKeyType(keyType); err != nil {
		return nil, err
	}
	switch keyType {
	case KeyTypeEd25519:
		private, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("device signer is not Ed25519")
		}
		return ed25519.Sign(private, message), nil
	case KeyTypeECDSAP256:
		private, ok := key.(*ecdsa.PrivateKey)
		if !ok || private.Curve != elliptic.P256() {
			return nil, errors.New("device signer is not ECDSA P-256")
		}
		hash := crypto.SHA256.New()
		hash.Write(message)
		return ecdsa.SignASN1(rand.Reader, private, hash.Sum(nil))
	default:
		return nil, errors.New("unsupported device key type")
	}
}
