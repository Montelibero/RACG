package rules

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"
)

type CommandAnalysis struct {
	OriginalArgv []string
	Segments     []CommandSegment
	Shell        bool
	Unsupported  string
}

type CommandSegment struct {
	Argv        []string
	Source      string
	Unsupported string
}

func AnalyzeCommandOp(op Op) CommandAnalysis {
	var p struct {
		Argv []string `json:"argv"`
	}
	if op.Type != "cmd.run" {
		return CommandAnalysis{Unsupported: "unsupported op type"}
	}
	if err := json.Unmarshal(op.Payload, &p); err != nil || len(p.Argv) == 0 {
		return CommandAnalysis{Unsupported: "invalid cmd.run payload"}
	}
	return AnalyzeCommandArgv(p.Argv)
}

func AnalyzeCommandArgv(argv []string) CommandAnalysis {
	out := CommandAnalysis{OriginalArgv: append([]string(nil), argv...)}
	if script, ok := shellScriptArg(argv); ok {
		out.Shell = true
		out.Segments, out.Unsupported = analyzeShellScript(script)
		return out
	}
	out.Segments = []CommandSegment{{Argv: append([]string(nil), argv...), Source: strings.Join(argv, " ")}}
	return out
}

func shellScriptArg(argv []string) (string, bool) {
	if len(argv) < 3 {
		return "", false
	}
	name := argv[0]
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	if name != "sh" && name != "bash" {
		return "", false
	}
	for i := 1; i < len(argv)-1; i++ {
		arg := argv[i]
		if arg == "-c" || arg == "-lc" {
			return argv[i+1], true
		}
		if strings.Contains(arg, "c") && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			return argv[i+1], true
		}
	}
	return "", false
}

func analyzeShellScript(script string) ([]CommandSegment, string) {
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil {
		return nil, "shell parse error: " + err.Error()
	}
	var segments []CommandSegment
	for _, stmt := range file.Stmts {
		segments = append(segments, segmentsFromStmt(stmt)...)
	}
	return segments, ""
}

func segmentsFromStmt(stmt *syntax.Stmt) []CommandSegment {
	if stmt == nil {
		return nil
	}
	if len(stmt.Redirs) > 0 && !allRedirsAreFdDup(stmt.Redirs) {
		return []CommandSegment{{Source: nodeSource(stmt), Unsupported: "redirect"}}
	}
	return segmentsFromCommand(stmt.Cmd)
}

func allRedirsAreFdDup(redirs []*syntax.Redirect) bool {
	for _, redir := range redirs {
		if !isFdDupRedir(redir) {
			return false
		}
	}
	return true
}

func isFdDupRedir(redir *syntax.Redirect) bool {
	if redir == nil {
		return false
	}
	op := redir.Op.String()
	if op != ">&" && op != "<&" {
		return false
	}
	word, ok := staticWord(redir.Word)
	if !ok {
		return false
	}
	return word == "-" || isDigits(word)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func segmentsFromCommand(cmd syntax.Command) []CommandSegment {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		return []CommandSegment{segmentFromCall(c)}
	case *syntax.BinaryCmd:
		var out []CommandSegment
		out = append(out, segmentsFromStmt(c.X)...)
		out = append(out, segmentsFromStmt(c.Y)...)
		return out
	case *syntax.Block:
		var out []CommandSegment
		for _, stmt := range c.Stmts {
			out = append(out, segmentsFromStmt(stmt)...)
		}
		return out
	case *syntax.Subshell:
		var out []CommandSegment
		for _, stmt := range c.Stmts {
			out = append(out, segmentsFromStmt(stmt)...)
		}
		return out
	default:
		return []CommandSegment{{Source: nodeSource(cmd), Unsupported: "unsupported shell construct"}}
	}
}

func segmentFromCall(c *syntax.CallExpr) CommandSegment {
	argv := make([]string, 0, len(c.Args))
	for _, word := range c.Args {
		arg, ok := staticWord(word)
		if !ok {
			return CommandSegment{Source: nodeSource(c), Unsupported: "dynamic shell word"}
		}
		argv = append(argv, arg)
	}
	if len(argv) == 0 {
		return CommandSegment{Source: nodeSource(c), Unsupported: "empty command"}
	}
	return CommandSegment{Argv: argv, Source: strings.Join(argv, " ")}
}

func staticWord(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, qp := range p.Parts {
				lit, ok := qp.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func nodeSource(node syntax.Node) string {
	var b bytes.Buffer
	_ = syntax.NewPrinter().Print(&b, node)
	return b.String()
}
