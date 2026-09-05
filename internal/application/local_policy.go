package application

import (
	"encoding/json"
	"strings"

	"github.com/itolstov/racg/internal/rules"
)

// These helpers preserve the interactive policy. Risk flags are review aids,
// not a sandbox or a substitute for service-mode signature verification.
func RuleMayMatchDangerousOperation(rule rules.Rule) bool {
	if rule.OpType == "cmd.run" && rule.Cmd != nil {
		argv := rule.Cmd.ArgvPrefix
		if len(argv) == 0 || strings.Contains(argv[0], "*") {
			return true
		}
		executable := manualRuleExecutableBase(argv[0])
		if manualRuleUsesDangerousWrapper(executable) {
			return true
		}
		normalizedArgv := append([]string(nil), argv...)
		normalizedArgv[0] = executable
		payload, _ := json.Marshal(map[string]any{"argv": normalizedArgv})
		if IsDangerous(RiskFlags(rules.Op{Type: "cmd.run", Payload: payload})) {
			return true
		}
		switch executable {
		case "apt", "apt-get":
			return len(argv) < 2 || strings.Contains(argv[1], "*")
		case "systemctl":
			if len(argv) < 2 || strings.Contains(argv[1], "*") {
				return true
			}
			if argv[1] == "stop" || argv[1] == "disable" {
				return len(argv) < 3 || strings.Contains(argv[2], "*") || strings.Contains(argv[2], "ssh")
			}
		}
		return false
	}

	switch rule.OpType {
	case "fs.patch_unified", "fs.upload", "fs.append_block", "fs.replace_literal", "conf.set", "conf.set_kv":
		return rule.Path != nil && pathRuleMayMatchEtc(*rule.Path)
	default:
		return false
	}
}

func manualRuleExecutableBase(executable string) string {
	if i := strings.LastIndexByte(executable, '/'); i >= 0 {
		return executable[i+1:]
	}
	return executable
}

func manualRuleUsesDangerousWrapper(executable string) bool {
	switch executable {
	case "sudo", "doas", "su", "sh", "bash", "dash", "zsh", "ksh", "fish", "env", "command", "nohup", "nice", "timeout", "chroot", "xargs":
		return true
	default:
		return false
	}
}

func pathRuleMayMatchEtc(rule rules.PathRule) bool {
	if rule.Exact != "" {
		return rule.Exact == "/etc" || strings.HasPrefix(rule.Exact, "/etc/")
	}
	if rule.Prefix != "" {
		return strings.HasPrefix("/etc/", rule.Prefix) || rule.Prefix == "/etc" || strings.HasPrefix(rule.Prefix, "/etc/")
	}
	if rule.Glob != "" {
		literalPrefix := rule.Glob
		if i := strings.IndexAny(literalPrefix, "*?["); i >= 0 {
			literalPrefix = literalPrefix[:i]
		}
		return literalPrefix == "" || strings.HasPrefix("/etc/", literalPrefix) || literalPrefix == "/etc" || strings.HasPrefix(literalPrefix, "/etc/")
	}
	return false
}

func RuleFromOpExact(ruleID string, op rules.Op) (rules.Rule, bool) {
	switch op.Type {
	case "cmd.run":
		var p struct {
			Argv []string `json:"argv"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil || len(p.Argv) == 0 {
			return rules.Rule{}, false
		}
		return rules.Rule{ID: ruleID, OpType: "cmd.run", Cmd: &rules.CmdRule{ArgvPrefix: p.Argv}}, true
	case "fs.read", "fs.download":
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil || p.Path == "" {
			return rules.Rule{}, false
		}
		return rules.Rule{ID: ruleID, OpType: op.Type, Path: &rules.PathRule{Exact: p.Path}}, true
	case "fs.patch_unified", "fs.upload":
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil || p.Path == "" {
			return rules.Rule{}, false
		}
		return rules.Rule{ID: ruleID, OpType: op.Type, Path: &rules.PathRule{Exact: p.Path}}, true
	case "conf.set":
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(op.Payload, &p); err != nil || p.Path == "" {
			return rules.Rule{}, false
		}
		return rules.Rule{ID: ruleID, OpType: "conf.set", Path: &rules.PathRule{Exact: p.Path}}, true
	default:
		return rules.Rule{}, false
	}
}

func RiskFlags(op rules.Op) []string {
	var flags []string
	switch op.Type {
	case "cmd.run":
		var p struct {
			Argv []string `json:"argv"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if len(p.Argv) > 0 {
			bin := p.Argv[0]
			switch bin {
			case "iptables", "nft", "ufw":
				flags = append(flags, "FIREWALL")
			case "rm", "/bin/rm":
				flags = append(flags, "DESTRUCTIVE_FS")
			}
			if bin == "apt" || bin == "apt-get" {
				for _, a := range p.Argv[1:] {
					if a == "remove" || a == "purge" {
						flags = append(flags, "APT_REMOVE")
						break
					}
					if a == "install" {
						flags = append(flags, "APT_INSTALL")
					}
				}
			}
			if bin == "systemctl" {
				for i := 1; i < len(p.Argv); i++ {
					if (p.Argv[i] == "stop" || p.Argv[i] == "disable") && i+1 < len(p.Argv) {
						unit := p.Argv[i+1]
						if strings.Contains(unit, "ssh") {
							flags = append(flags, "SERVICE_SSH_RISK")
							break
						}
					}
				}
			}
		}
	case "fs.patch_unified", "fs.upload", "conf.set", "conf.set_kv":
		var p struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if strings.HasPrefix(p.Path, "/etc/") {
			flags = append(flags, "WRITE_ETC")
		}
	}
	return flags
}

func IsDangerous(flags []string) bool {
	for _, f := range flags {
		switch f {
		case "WRITE_ETC", "APT_REMOVE", "FIREWALL", "DESTRUCTIVE_FS", "SERVICE_SSH_RISK":
			return true
		}
	}
	return false
}
