package rules

import (
	"encoding/json"
	"path/filepath"
)

// CanonicalizeOpPath resolves symlinks in the path field of fs.*/conf.*
// operations before rule matching. A static link inside an allowed
// directory cannot smuggle a target outside the rule scope: rules see the
// kernel-resolved location. fs.upload resolves the parent directory (the
// file itself may not exist yet). Paths that fail to resolve (missing
// file) are returned unchanged: admission owns the canonical-path
// contract and execution fails loudly on its own. The stored operation
// bytes stay verbatim — only the matching copy is rewritten.
func CanonicalizeOpPath(op Op) Op {
	if op.Payload == nil {
		return op
	}
	var payload struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(op.Payload, &payload); err != nil || payload.Path == "" || !filepath.IsAbs(payload.Path) {
		return op
	}
	resolved := resolveOperationPath(op.Type, payload.Path)
	if resolved == payload.Path {
		return op
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(op.Payload, &fields); err != nil {
		return op
	}
	raw, err := json.Marshal(resolved)
	if err != nil {
		return op
	}
	fields["path"] = raw
	out, err := json.Marshal(fields)
	if err != nil {
		return op
	}
	op.Payload = out
	return op
}

func resolveOperationPath(opType, path string) string {
	if opType == "fs.upload" {
		return filepath.Join(evalSymlinksBestEffort(filepath.Dir(path)), filepath.Base(path))
	}
	return evalSymlinksBestEffort(path)
}

func evalSymlinksBestEffort(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}
