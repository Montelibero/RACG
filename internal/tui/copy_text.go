package tui

import "fmt"

func PairingCopyText(listenURL, code string) string {
	return fmt.Sprintf("listening=%s\npairing_code=%s\nRACG_CODE=%s\nopen_session --code %s\n", listenURL, code, code, code)
}
