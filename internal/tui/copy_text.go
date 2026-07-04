package tui

import "fmt"

func PairingCopyText(listenURL, code, version string) string {
	return fmt.Sprintf("listening=%s\nversion=%s\npairing_code=%s\nRACG_CODE=%s\nopen_session --code %s\n", listenURL, version, code, code, code)
}
