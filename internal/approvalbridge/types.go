package approvalbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type PhoneRequest struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	ClientID  string          `json:"client_id,omitempty"`
	Op        json.RawMessage `json:"op"`
	OpSHA256  string          `json:"op_sha256"`
	CreatedAt string          `json:"created_at,omitempty"`
	Summary   string          `json:"summary"`
}

type PhoneDecision struct {
	DeviceID  string `json:"device_id"`
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
	OpSHA256  string `json:"op_sha256"`
	Challenge string `json:"challenge"`
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
}

func DecisionMessage(deviceID, requestID, decision, opSHA256, challenge string) []byte {
	message := "racg/phone-decision/v1\x00" + deviceID + "\x00" + requestID + "\x00" + decision + "\x00" + opSHA256 + "\x00" + challenge
	return []byte(message)
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
