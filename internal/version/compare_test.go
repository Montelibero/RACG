package version

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.4.2", "0.4.1", 1},
		{"v0.4.1", "0.4.1", 0},
		{"0.4.1", "0.4.2", -1},
		{"0.4.2", "0.4.2-rc.1", 1},
		{"0.4.2-rc.2", "0.4.2-rc.1", 1},
	}
	for _, tt := range tests {
		if got := Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q)=%d want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
