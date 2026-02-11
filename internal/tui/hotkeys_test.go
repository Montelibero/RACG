package tui

import "testing"

func TestHotkeyRuneLayoutMapping(t *testing.T) {
	tests := []struct {
		in   rune
		want rune
	}{
		{'q', 'q'},
		{'Q', 'q'},
		{'й', 'q'}, // q key in RU layout
		{'к', 'r'}, // r key in RU layout
		{'р', 'h'}, // h key in RU layout
		{'ф', 'a'}, // a key in RU layout
		{'ы', 's'}, // s key in RU layout
		{'в', 'd'}, // d key in RU layout
		{'с', 'c'}, // c key in RU layout
		{'а', 'f'}, // f key in RU layout
	}

	for _, tt := range tests {
		if got := hotkeyRune(tt.in); got != tt.want {
			t.Fatalf("hotkeyRune(%q)=%q, want %q", string(tt.in), string(got), string(tt.want))
		}
	}
}
