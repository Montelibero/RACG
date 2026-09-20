package httpapi

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

func verifyECDSAP256(publicKey, message, signature []byte) error {
	key, err := parseECDSAP256PublicKey(publicKey)
	if err != nil {
		return err
	}
	return verifyECDSAP256Key(key, message, signature)
}

func verifyECDSAP256Key(key *ecdsa.PublicKey, message, signature []byte) error {
	hash := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(key, hash[:], signature) {
		return errors.New("invalid ECDSA signature")
	}
	return nil
}

func parseECDSAP256PublicKey(encoded []byte) (*ecdsa.PublicKey, error) {
	public, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	key, ok := public.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA P-256")
	}
	if key.Curve.Params() == nil || key.Curve.Params().Name != "P-256" {
		return nil, errors.New("public key curve is not P-256")
	}
	return key, nil
}
