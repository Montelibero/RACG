package version

import (
	"strconv"
	"strings"
)

// Compare returns -1, 0, or 1 when a is older than, equal to, or newer than b.
func Compare(a, b string) int {
	aCore, aPre := splitVersion(a)
	bCore, bPre := splitVersion(b)
	if cmp := compareNumericParts(aCore, bCore); cmp != 0 {
		return cmp
	}
	if aPre == "" && bPre != "" {
		return 1
	}
	if aPre != "" && bPre == "" {
		return -1
	}
	return comparePrerelease(aPre, bPre)
}

func splitVersion(value string) ([]string, string) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	value = strings.SplitN(value, "+", 2)[0]
	parts := strings.SplitN(value, "-", 2)
	if len(parts) == 2 {
		return strings.Split(parts[0], "."), parts[1]
	}
	return strings.Split(parts[0], "."), ""
}

func compareNumericParts(a, b []string) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av := numericPart(a, i)
		bv := numericPart(b, i)
		if av > bv {
			return 1
		}
		if av < bv {
			return -1
		}
	}
	return 0
}

func numericPart(parts []string, index int) int {
	if index >= len(parts) {
		return 0
	}
	value, _ := strconv.Atoi(parts[index])
	return value
}

func comparePrerelease(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		av, aErr := strconv.Atoi(aParts[i])
		bv, bErr := strconv.Atoi(bParts[i])
		switch {
		case aErr == nil && bErr == nil && av != bv:
			if av < bv {
				return -1
			}
			return 1
		case aErr == nil && bErr != nil:
			return -1
		case aErr != nil && bErr == nil:
			return 1
		case aParts[i] < bParts[i]:
			return -1
		case aParts[i] > bParts[i]:
			return 1
		}
	}
	if len(aParts) < len(bParts) {
		return -1
	}
	if len(aParts) > len(bParts) {
		return 1
	}
	return 0
}
