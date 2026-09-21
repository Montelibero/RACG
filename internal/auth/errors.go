package auth

import "errors"

var (
	ErrPairingCodeInvalid = errors.New("PAIRING_CODE_INVALID")
	ErrPairingCodeExpired = errors.New("PAIRING_CODE_EXPIRED")
	ErrPairingCodeLocked  = errors.New("PAIRING_CODE_LOCKED")
	ErrPairingCodeUsed    = errors.New("PAIRING_CODE_USED")

	ErrUnauthorized   = errors.New("UNAUTHORIZED")
	ErrSessionExpired = errors.New("SESSION_EXPIRED")

	ErrSessionNotFound = errors.New("SESSION_NOT_FOUND")
)
