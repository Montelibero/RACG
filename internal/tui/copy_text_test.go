package tui

import "testing"

func TestPairingCopyText(t *testing.T) {
	listen := "http://127.0.0.1:8777"
	code := "GQ6BN2"
	got := PairingCopyText(listen, code)

	wantSubs := []string{
		"listening=" + listen,
		"pairing_code=" + code,
		"RACG_CODE=" + code,
		"open_session --code " + code,
	}
	for _, sub := range wantSubs {
		if !containsLine(got, sub) {
			t.Fatalf("missing line %q in:\n%s", sub, got)
		}
	}
}

func containsLine(s, line string) bool {
	// Cheap exact-line matcher to keep output copy-friendly.
	start := 0
	for start <= len(s) {
		end := start
		for end < len(s) && s[end] != '\n' {
			end++
		}
		if s[start:end] == line {
			return true
		}
		if end == len(s) {
			break
		}
		start = end + 1
	}
	return false
}
