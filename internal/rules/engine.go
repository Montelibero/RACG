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
	ArgvPrefix  []string
	TailAny     bool
	StdinSHA256 string
}

type PathRule struct {
	Exact  string
	Prefix string
	Glob   string
}

type Match struct {
	RuleID           string
	Source           string // "session" | "always"
	SegmentDecisions []SegmentDecision
}

type SegmentDecision struct {
	Argv        []string
	SourceText  string
	Source      string
	RuleID      string
	Allowed     bool
	Unsupported string
	Reason      string
}

type Explanation struct {
	Allowed  bool
	Segments []SegmentDecision
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

	if op.Type == "cmd.run" && cmdRunStdinSHA256(op) == "" {
		if m, ok := matchAnalyzedCommand(sess, always, op); ok || len(m.SegmentDecisions) > 0 {
			return m, ok
		}
	}

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

func (e *Engine) Explain(sessionID string, op Op) Explanation {
	e.mu.Lock()
	sess := append([]Rule(nil), e.sessionRules[sessionID]...)
	always := append([]Rule(nil), e.always...)
	e.mu.Unlock()

	if op.Type == "cmd.run" && cmdRunStdinSHA256(op) == "" {
		if m, ok := matchAnalyzedCommand(sess, always, op); ok || len(m.SegmentDecisions) > 0 {
			fillSegmentReasons(m.SegmentDecisions)
			return Explanation{Allowed: ok, Segments: m.SegmentDecisions}
		}
	}

	analysis := AnalyzeCommandOp(op)
	if op.Type == "cmd.run" && cmdRunStdinSHA256(op) != "" {
		decision := SegmentDecision{Argv: append([]string(nil), analysis.OriginalArgv...), SourceText: strings.Join(analysis.OriginalArgv, " ")}
		for _, candidate := range []struct {
			source string
			rules  []Rule
		}{{"session", sess}, {"always", always}} {
			for _, rule := range candidate.rules {
				if ruleMatches(rule, op) {
					decision.Allowed = true
					decision.Source = candidate.source
					decision.RuleID = rule.ID
					return Explanation{Allowed: true, Segments: []SegmentDecision{decision}}
				}
			}
		}
		decision.Reason = "no matching rule for stdin sha256"
		return Explanation{Segments: []SegmentDecision{decision}}
	}
	segments := make([]SegmentDecision, 0, len(analysis.Segments))
	for _, segment := range analysis.Segments {
		decision := SegmentDecision{Argv: append([]string(nil), segment.Argv...), SourceText: segment.Source, Unsupported: segment.Unsupported}
		if segment.Unsupported != "" {
			decision.Reason = segment.Unsupported
		} else if r, ok := matchCmdArgvRules(sess, segment.Argv); ok {
			decision.Allowed = true
			decision.Source = "session"
			decision.RuleID = r.ID
		} else if r, ok := matchCmdArgvRules(always, segment.Argv); ok {
			decision.Allowed = true
			decision.Source = "always"
			decision.RuleID = r.ID
		} else {
			decision.Reason = "no matching rule"
		}
		segments = append(segments, decision)
	}
	allowed := len(segments) > 0
	for _, segment := range segments {
		if !segment.Allowed {
			allowed = false
			break
		}
	}
	return Explanation{Allowed: allowed, Segments: segments}
}

func fillSegmentReasons(segments []SegmentDecision) {
	for i := range segments {
		if segments[i].Allowed {
			continue
		}
		if segments[i].Unsupported != "" {
			segments[i].Reason = segments[i].Unsupported
			continue
		}
		segments[i].Reason = "no matching rule"
	}
}

func matchAnalyzedCommand(sess []Rule, always []Rule, op Op) (Match, bool) {
	analysis := AnalyzeCommandOp(op)
	if !analysis.Shell {
		return Match{}, false
	}
	if analysis.Unsupported != "" || len(analysis.Segments) == 0 {
		return Match{SegmentDecisions: []SegmentDecision{{Unsupported: analysis.Unsupported}}}, false
	}

	out := Match{RuleID: "shell-segments", Source: "segments"}
	allAllowed := true
	for _, segment := range analysis.Segments {
		decision := SegmentDecision{Argv: append([]string(nil), segment.Argv...), SourceText: segment.Source, Unsupported: segment.Unsupported}
		if segment.Unsupported != "" {
			allAllowed = false
			out.SegmentDecisions = append(out.SegmentDecisions, decision)
			continue
		}
		if r, ok := matchCmdArgvRules(sess, segment.Argv); ok {
			decision.Allowed = true
			decision.Source = "session"
			decision.RuleID = r.ID
			out.SegmentDecisions = append(out.SegmentDecisions, decision)
			continue
		}
		if r, ok := matchCmdArgvRules(always, segment.Argv); ok {
			decision.Allowed = true
			decision.Source = "always"
			decision.RuleID = r.ID
			out.SegmentDecisions = append(out.SegmentDecisions, decision)
			continue
		}
		allAllowed = false
		out.SegmentDecisions = append(out.SegmentDecisions, decision)
	}
	return out, allAllowed
}

func matchCmdArgvRules(rs []Rule, argv []string) (Rule, bool) {
	for _, r := range rs {
		if r.OpType != "cmd.run" || r.Cmd == nil {
			continue
		}
		if r.Cmd.StdinSHA256 != "" {
			continue
		}
		if argvHasPrefix(argv, r.Cmd.ArgvPrefix) {
			return r, true
		}
	}
	return Rule{}, false
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
			Argv        []string `json:"argv"`
			StdinSHA256 string   `json:"stdin_sha256"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return false
		}
		return argvHasPrefix(p.Argv, r.Cmd.ArgvPrefix) && p.StdinSHA256 == r.Cmd.StdinSHA256
	case "fs.read", "fs.patch_unified", "fs.upload", "fs.download", "fs.append_block", "fs.replace_literal", "conf.set", "conf.set_kv":
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

func cmdRunStdinSHA256(op Op) string {
	if op.Type != "cmd.run" {
		return ""
	}
	var payload struct {
		StdinSHA256 string `json:"stdin_sha256"`
	}
	if json.Unmarshal(op.Payload, &payload) != nil {
		return ""
	}
	return strings.TrimSpace(payload.StdinSHA256)
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
