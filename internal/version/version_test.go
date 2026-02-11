package version

import "testing"

func TestVersionNonEmpty(t *testing.T) {
	if Version == "" {
		t.Fatalf("Version must be non-empty")
	}
}

func TestVersionAddressable(t *testing.T) {
	_ = &Version
}
