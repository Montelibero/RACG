package executor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// PatchFile applies an already-authorized unified patch using the existing patch semantics.
func PatchFile(path, diff string) Result {
	start := time.Now()
	err := applyUnifiedPatchToFile(path, diff)
	return fileEditResult(start, "patched", err)
}

func applyUnifiedPatchToFile(path string, diff string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path required")
	}
	if strings.TrimSpace(diff) == "" {
		return fmt.Errorf("diff required")
	}

	origBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	orig := string(origBytes)

	next, err := applyUnifiedPatchText(orig, diff)
	if err != nil {
		return err
	}

	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(path, []byte(next), mode)
}

func applyUnifiedPatchText(original string, diff string) (string, error) {
	endsWithNewline := strings.HasSuffix(original, "\n")
	origBody := strings.TrimSuffix(original, "\n")
	var origLines []string
	if origBody == "" {
		origLines = []string{}
	} else {
		origLines = strings.Split(origBody, "\n")
	}

	diff = strings.ReplaceAll(diff, "\r\n", "\n")
	patchLines := strings.Split(diff, "\n")

	out := make([]string, 0, len(origLines)+16)
	cur := 0
	i := 0
	resultEndsWithNewline := false
	hasOutput := false
	var lastHunkLine byte
	for i < len(patchLines) {
		line := patchLines[i]
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "diff ") || strings.HasPrefix(line, "index ") {
			i++
			continue
		}
		if strings.HasPrefix(line, "@@") {
			oldStart, err := parseUnifiedHunkOldStart(line)
			if err != nil {
				return "", err
			}
			target := oldStart - 1
			if oldStart == 0 {
				target = 0
			}
			if target < cur || target > len(origLines) {
				return "", fmt.Errorf("hunk out of range")
			}
			out = append(out, origLines[cur:target]...)
			if target > cur {
				hasOutput = true
				resultEndsWithNewline = target < len(origLines) || endsWithNewline
				lastHunkLine = 0
			}
			cur = target
			i++

			for i < len(patchLines) && !strings.HasPrefix(patchLines[i], "@@") {
				hl := patchLines[i]
				if hl == "" {
					// Trailing newline in diff; ignore.
					i++
					continue
				}
				switch hl[0] {
				case ' ':
					want := hl[1:]
					if cur >= len(origLines) || origLines[cur] != want {
						return "", fmt.Errorf("hunk context mismatch")
					}
					out = append(out, want)
					cur++
					hasOutput = true
					resultEndsWithNewline = true
					lastHunkLine = ' '
				case '-':
					want := hl[1:]
					if cur >= len(origLines) || origLines[cur] != want {
						return "", fmt.Errorf("hunk delete mismatch")
					}
					cur++
					lastHunkLine = '-'
				case '+':
					out = append(out, hl[1:])
					hasOutput = true
					resultEndsWithNewline = true
					lastHunkLine = '+'
				case '\\':
					if lastHunkLine == '+' || lastHunkLine == ' ' {
						resultEndsWithNewline = false
					}
				default:
					return "", fmt.Errorf("invalid patch line")
				}
				i++
			}
			continue
		}
		i++
	}

	remaining := origLines[cur:]
	out = append(out, remaining...)
	if len(remaining) > 0 {
		hasOutput = true
		resultEndsWithNewline = endsWithNewline
	}
	res := strings.Join(out, "\n")
	if hasOutput && resultEndsWithNewline {
		res += "\n"
	}
	return res, nil
}

func parseUnifiedHunkOldStart(header string) (int, error) {
	// Expect: @@ -oldStart,oldCount +newStart,newCount @@
	fields := strings.Fields(header)
	if len(fields) < 3 {
		return 0, fmt.Errorf("invalid hunk header")
	}
	rng := fields[1] // "-1,3"
	rng = strings.TrimPrefix(rng, "-")
	parts := strings.SplitN(rng, ",", 2)
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid hunk range")
	}
	return n, nil
}
