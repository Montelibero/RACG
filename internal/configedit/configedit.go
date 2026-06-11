package configedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ConfigSet struct {
	Path      string
	Format    string
	Key       string
	Value     string
	ValueType string
	Backup    bool
	BackupDir string
}

type Result struct {
	Path       string
	Format     string
	Key        string
	OldValue   string
	NewValue   string
	Created    bool
	BackupPath string
}

func Set(in ConfigSet) (Result, error) {
	if strings.TrimSpace(in.Path) == "" {
		return Result{}, errors.New("path is required")
	}
	format := normalizeFormat(in.Format, in.Path)
	if format == "" {
		return Result{}, errors.New("format is required")
	}
	key := strings.TrimSpace(in.Key)
	if key == "" {
		return Result{}, errors.New("key is required")
	}
	valueType := strings.TrimSpace(in.ValueType)
	if valueType == "" {
		valueType = "string"
	}

	original, err := os.ReadFile(in.Path)
	if err != nil {
		return Result{}, err
	}

	var updated []byte
	var oldValue string
	var created bool
	switch format {
	case "env":
		updated, oldValue, created, err = setEnv(original, key, in.Value)
	case "json":
		updated, oldValue, created, err = setJSON(original, key, in.Value, valueType)
	case "yaml":
		updated, oldValue, created, err = setYAML(original, key, in.Value, valueType)
	default:
		return Result{}, fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return Result{}, err
	}

	var backupPath string
	if in.Backup {
		backupPath, err = writeBackup(in.Path, in.BackupDir, original)
		if err != nil {
			return Result{}, err
		}
	}
	if err := writeFileAtomic(in.Path, updated); err != nil {
		return Result{}, err
	}
	return Result{
		Path:       in.Path,
		Format:     format,
		Key:        key,
		OldValue:   oldValue,
		NewValue:   resultValue(in.Value, valueType),
		Created:    created,
		BackupPath: backupPath,
	}, nil
}

func normalizeFormat(format, path string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "yml":
		return "yaml"
	}
	if format != "" {
		return format
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".env":
		return "env"
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	}
	if filepath.Base(path) == ".env" {
		return "env"
	}
	return ""
}

func setEnv(original []byte, key, value string) ([]byte, string, bool, error) {
	lines := strings.SplitAfter(string(original), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	prefix := key + "="
	for i, line := range lines {
		body := strings.TrimSuffix(line, "\n")
		body = strings.TrimSuffix(body, "\r")
		trimmed := strings.TrimSpace(body)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "export ") {
			continue
		}
		if strings.HasPrefix(body, prefix) {
			old := strings.TrimPrefix(body, prefix)
			lineEnd := ""
			if strings.HasSuffix(line, "\n") {
				lineEnd = "\n"
			}
			lines[i] = prefix + value + lineEnd
			return []byte(strings.Join(lines, "")), old, false, nil
		}
	}
	out := string(original)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += prefix + value + "\n"
	return []byte(out), "", true, nil
}

func setJSON(original []byte, key, rawValue, valueType string) ([]byte, string, bool, error) {
	var root any
	if err := json.Unmarshal(original, &root); err != nil {
		return nil, "", false, err
	}
	m, ok := root.(map[string]any)
	if !ok {
		return nil, "", false, errors.New("json root must be an object")
	}
	value, err := parseTypedValue(rawValue, valueType)
	if err != nil {
		return nil, "", false, err
	}
	old, created, err := setDotted(m, key, value)
	if err != nil {
		return nil, "", false, err
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, "", false, err
	}
	out = append(out, '\n')
	var check any
	if err := json.Unmarshal(out, &check); err != nil {
		return nil, "", false, err
	}
	return out, scalarString(old), created, nil
}

func setYAML(original []byte, key, rawValue, valueType string) ([]byte, string, bool, error) {
	var root map[string]any
	if err := yaml.Unmarshal(original, &root); err != nil {
		return nil, "", false, err
	}
	if root == nil {
		root = map[string]any{}
	}
	value, err := parseTypedValue(rawValue, valueType)
	if err != nil {
		return nil, "", false, err
	}
	old, created, err := setDotted(root, key, value)
	if err != nil {
		return nil, "", false, err
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return nil, "", false, err
	}
	var check any
	if err := yaml.Unmarshal(out, &check); err != nil {
		return nil, "", false, err
	}
	return out, scalarString(old), created, nil
}

func setDotted(root map[string]any, key string, value any) (any, bool, error) {
	parts := strings.Split(key, ".")
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return nil, false, fmt.Errorf("invalid key %q", key)
		}
	}
	cur := root
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part]
		if !ok {
			m := map[string]any{}
			cur[part] = m
			cur = m
			continue
		}
		m, ok := next.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("key %q is not an object", part)
		}
		cur = m
	}
	last := parts[len(parts)-1]
	old, ok := cur[last]
	cur[last] = value
	return old, !ok, nil
}

func parseTypedValue(value, valueType string) (any, error) {
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "", "string":
		return value, nil
	case "bool":
		return strconv.ParseBool(value)
	case "int":
		return strconv.Atoi(value)
	case "float":
		return strconv.ParseFloat(value, 64)
	case "null":
		return nil, nil
	case "json":
		var out any
		if err := json.Unmarshal([]byte(value), &out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported value_type %q", valueType)
	}
}

func scalarString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}

func resultValue(value, valueType string) string {
	if strings.EqualFold(strings.TrimSpace(valueType), "null") {
		return "null"
	}
	parsed, err := parseTypedValue(value, valueType)
	if err != nil {
		return value
	}
	return scalarString(parsed)
}

func writeBackup(path, backupDir string, original []byte) (string, error) {
	dir := filepath.Dir(path)
	if strings.TrimSpace(backupDir) != "" {
		dir = backupDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := filepath.Base(path) + ".racg-backup-" + time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(dir, name)
	if err := os.WriteFile(backupPath, original, 0o600); err != nil {
		return "", err
	}
	return backupPath, nil
}

func writeFileAtomic(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".racg-config-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := bytes.NewReader(data).WriteTo(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
