package main

import (
	"strconv"
	"strings"
	"unicode"
)

// ServerProfile must come from trusted SSH enrollment, never from the broker
// message being inspected. PublicKey is a base64-encoded Ed25519 public key.
type ServerProfile struct {
	ServerID  string `json:"server_id"`
	PublicKey []byte `json:"public_key"`
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
