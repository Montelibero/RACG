package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/itolstov/racg/internal/approval"
)

// ServerProfile must come from trusted SSH enrollment, never from the broker
// message being inspected. PublicKey is a base64-encoded Ed25519 public key.
type ServerProfile struct {
	ServerID  string `json:"server_id"`
	PublicKey []byte `json:"public_key"`
}

func verifiedPreview(profile ServerProfile, data []byte) (string, error) {
	var signed approval.SignedRequest
	if err := json.Unmarshal(data, &signed); err != nil {
		return "", fmt.Errorf("decode signed request: %w", err)
	}
	if err := approval.VerifyRequest(signed, profile.ServerID, ed25519.PublicKey(profile.PublicKey)); err != nil {
		return "", err
	}
	digest, err := approval.RequestDigest(signed.Request)
	if err != nil {
		return "", err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, signed.Request.Operation, "", "  "); err != nil {
		return "", err
	}
	text := fmt.Sprintf("Server: %s\nAgent: %s\nRequest: %s\nDigest: %s\n\nSigned operation:\n%s",
		strconv.QuoteToASCII(signed.Request.ServerID), strconv.QuoteToASCII(signed.Request.ClientID), strconv.QuoteToASCII(signed.Request.RequestID), digest, pretty.String())
	return visibleText(text), nil
}

// Preserve review layout while making bidi and other invisible formatting
// characters visible. These display escapes never change signed bytes.
func visibleText(text string) string {
	var b strings.Builder
	for _, r := range text {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
