package cli

import (
	"fmt"
	"strings"

	"github.com/itolstov/racg/internal/outputfilter"
)

func redactOutput(text string) string {
	return outputfilter.Redact(text)
}

func visibleOutput(text string, unredacted bool) string {
	if unredacted {
		return text
	}
	return redactOutput(text)
}

func numberOutputLines(text string) string {
	if text == "" {
		return ""
	}
	hasFinalNewline := strings.HasSuffix(text, "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	width := len(fmt.Sprint(len(lines)))
	var out strings.Builder
	for i, line := range lines {
		fmt.Fprintf(&out, "%*d | %s", width, i+1, line)
		if i < len(lines)-1 || hasFinalNewline {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func filterRequestOutput(rec requestStatusResp, unredacted bool) requestStatusResp {
	if unredacted || rec.Result == nil {
		return rec
	}
	result := *rec.Result
	result.Stdout = redactOutput(result.Stdout)
	result.Stderr = redactOutput(result.Stderr)
	rec.Result = &result
	return rec
}
