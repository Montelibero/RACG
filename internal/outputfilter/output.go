package outputfilter

import "regexp"
import "strings"

const Placeholder = "[REDACTED]"

var secretPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?im)(\bauthorization\s*:\s*)(?:bearer\s+)?[^\r\n]+`), `${1}` + Placeholder},
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`), `Bearer ` + Placeholder},
	{regexp.MustCompile(`(?i)("(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|authorization)"\s*:\s*)("(?:\\.|[^"\\])*"|[^,\s}\]]+)`), `${1}"` + Placeholder + `"`},
	{regexp.MustCompile(`(?im)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)(\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s;,\r\n]+)`), `${1}${2}` + Placeholder},
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@/\s]+@`), `${1}` + Placeholder + `@`},
	{regexp.MustCompile(`(?i)\b(?:github_pat_|gh[pousr]_|sk-|xox[baprs]-)[A-Za-z0-9._=-]{8,}`), Placeholder},
}

var privateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----`)

// Redact masks common credential forms for display. It is intentionally
// best-effort; callers keep and audit the original bytes separately.
func Redact(text string) string {
	text = privateKeyPattern.ReplaceAllStringFunc(text, func(match string) string {
		return Placeholder + strings.Repeat("\n", strings.Count(match, "\n"))
	})
	for _, pattern := range secretPatterns {
		text = pattern.re.ReplaceAllString(text, pattern.replacement)
	}
	return text
}
