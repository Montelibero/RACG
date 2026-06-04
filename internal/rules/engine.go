package rules

import (
	"encoding/json"
	"strings"
	"sync"
)

type Op struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type Rule struct {
	ID     string
	OpType string

	Cmd  *CmdRule
	Path *PathRule
}

type CmdRule struct {
	ArgvPrefix []string
}

type PathRule struct {
	Exact  string
	Prefix string
	Glob   string
}

type Match struct {
	RuleID string
	Source string // "session" | "always"
}

type Engine struct {
	mu           sync.Mutex
	always       []Rule
	sessionRules map[string][]Rule
}

func NewEngine() *Engine {
	return &Engine{sessionRules: map[string][]Rule{}}
}

func (e *Engine) AddAlways(r Rule) {
	e.mu.Lock()
	e.always = append(e.always, r)
	e.mu.Unlock()
}

func (e *Engine) AddSession(sessionID string, r Rule) {
	e.mu.Lock()
	e.sessionRules[sessionID] = append(e.sessionRules[sessionID], r)
	e.mu.Unlock()
}

func (e *Engine) SessionRulesSnapshot() map[string][]Rule {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make(map[string][]Rule, len(e.sessionRules))
	for sessionID, rs := range e.sessionRules {
		out[sessionID] = append([]Rule(nil), rs...)
	}
	return out
}

func (e *Engine) Match(sessionID string, op Op) (Match, bool) {
	e.mu.Lock()
	sess := append([]Rule(nil), e.sessionRules[sessionID]...)
	always := append([]Rule(nil), e.always...)
	e.mu.Unlock()

	for _, r := range sess {
		if ruleMatches(r, op) {
			return Match{RuleID: r.ID, Source: "session"}, true
		}
	}
	for _, r := range always {
		if ruleMatches(r, op) {
			return Match{RuleID: r.ID, Source: "always"}, true
		}
	}
	return Match{}, false
}

func ruleMatches(r Rule, op Op) bool {
	if r.OpType != op.Type {
		return false
	}

	switch op.Type {
	case "cmd.run":
		if r.Cmd == nil {
			return false
		}
		var p struct {
			Argv []string `json:"argv"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return false
		}
		return argvHasPrefix(p.Argv, r.Cmd.ArgvPrefix)
	case "fs.read", "fs.patch_unified", "fs.append_block", "fs.replace_literal":
		if r.Path == nil {
			return false
		}
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return false
		}
		return pathMatches(p.Path, *r.Path)
	default:
		// MVP: only cmd.run + basic path operations.
		return false
	}
}

func argvHasPrefix(argv, prefix []string) bool {
	if len(prefix) == 0 {
		return false
	}
	if len(argv) < len(prefix) {
		return false
	}
	for i := range prefix {
		if strings.Contains(prefix[i], "*") {
			if !globMatch(prefix[i], argv[i]) {
				return false
			}
			continue
		}
		if argv[i] != prefix[i] {
			return false
		}
	}
	return true
}

func pathMatches(path string, r PathRule) bool {
	if r.Exact != "" {
		return path == r.Exact
	}
	if r.Prefix != "" {
		return strings.HasPrefix(path, r.Prefix)
	}
	if r.Glob != "" {
		return globMatch(r.Glob, path)
	}
	return false
}

// globMatch supports a minimal single-star glob: `prefix*suffix`.
func globMatch(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if strings.Count(pattern, "*") > 1 {
		return multiStarGlobMatch(pattern, s)
	}
	idx := strings.Index(pattern, "*")
	if idx < 0 {
		return pattern == s
	}
	pre := pattern[:idx]
	suf := pattern[idx+1:]
	if !strings.HasPrefix(s, pre) {
		return false
	}
	if suf == "" {
		return true
	}
	return strings.HasSuffix(s, suf)
}

func multiStarGlobMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 && !strings.HasPrefix(s, part) {
			return false
		}
		idx := strings.Index(s[pos:], part)
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
	}
	last := parts[len(parts)-1]
	if last != "" && !strings.HasSuffix(s, last) {
		return false
	}
	return true
}
