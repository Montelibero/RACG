package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type clientConfig struct {
	Host      string `json:"host"`
	Token     string `json:"token"`
	SessionID string `json:"session_id,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func clientConfigPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("RACG_CLIENT_CONFIG")); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "racg", "client.json"), nil
}

func clientConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "racg"), nil
}

func clientProfilesDir() (string, error) {
	dir, err := clientConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "clients"), nil
}

func activeClientProfilePath() (string, error) {
	dir, err := clientConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "active_client"), nil
}

func clientProfilePath(name string) (string, error) {
	name = sanitizeClientProfileName(name)
	if name == "" {
		return "", errors.New("profile name is required")
	}
	dir, err := clientProfilesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".json"), nil
}

func autoClientProfileName(host string) string {
	normalized := normalizeClientHost(host)
	if normalized == "" {
		return "default"
	}
	u, err := url.Parse(normalized)
	if err == nil && u.Hostname() != "" {
		return sanitizeClientProfileName(u.Hostname())
	}
	return sanitizeClientProfileName(normalized)
}

func normalizeClientHost(host string) string {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	if host == "" {
		return ""
	}
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}
	u, err := url.Parse(host)
	if err != nil || u.Host == "" {
		return host
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "8777")
	}
	return strings.TrimRight(u.String(), "/")
}

func sanitizeClientProfileName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func saveClientConfig(cfg clientConfig) error {
	if strings.TrimSpace(cfg.Host) == "" {
		return errors.New("host is required")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return errors.New("token is required")
	}
	p, err := clientConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(p, b, 0o600)
}

func saveNamedClientConfig(name string, cfg clientConfig) (string, error) {
	if strings.TrimSpace(os.Getenv("RACG_CLIENT_CONFIG")) != "" {
		if err := saveClientConfig(cfg); err != nil {
			return "", err
		}
		return clientConfigPath()
	}
	name = sanitizeClientProfileName(name)
	if name == "" {
		return "", errors.New("profile name is required")
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return "", errors.New("host is required")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return "", errors.New("token is required")
	}
	p, err := clientProfilePath(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return "", err
	}
	if err := setActiveClientProfile(name); err != nil {
		return "", err
	}
	return p, nil
}

func loadClientConfig() (clientConfig, error) {
	p, err := clientConfigPath()
	if err != nil {
		return clientConfig{}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return clientConfig{}, err
	}
	var cfg clientConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return clientConfig{}, err
	}
	if strings.TrimSpace(cfg.Host) == "" || strings.TrimSpace(cfg.Token) == "" {
		return clientConfig{}, fmt.Errorf("client config is missing host or token: %s", p)
	}
	return cfg, nil
}

func loadNamedClientConfig(name string) (clientConfig, error) {
	p, err := clientProfilePath(name)
	if err != nil {
		return clientConfig{}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return clientConfig{}, err
	}
	var cfg clientConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return clientConfig{}, err
	}
	if strings.TrimSpace(cfg.Host) == "" || strings.TrimSpace(cfg.Token) == "" {
		return clientConfig{}, fmt.Errorf("client profile is missing host or token: %s", p)
	}
	return cfg, nil
}

func setActiveClientProfile(name string) error {
	name = sanitizeClientProfileName(name)
	if name == "" {
		return errors.New("profile name is required")
	}
	p, err := activeClientProfilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(name+"\n"), 0o600)
}

func activeClientProfile() (string, error) {
	p, err := activeClientProfilePath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	name := sanitizeClientProfileName(string(b))
	if name == "" {
		return "", errors.New("active profile is empty")
	}
	return name, nil
}

func removeClientConfig() error {
	p, err := clientConfigPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func resolveClientAuth(hostFlag, tokenFlag string) (host string, token string, err error) {
	return resolveClientAuthNamed(hostFlag, tokenFlag, "")
}

func resolveClientAuthNamed(hostFlag, tokenFlag, nameFlag string) (host string, token string, err error) {
	host = normalizeClientHost(hostFlag)
	token = strings.TrimSpace(tokenFlag)
	if host != "" && token != "" {
		return host, token, nil
	}
	cfg, cfgErr := loadClientConfigForName(nameFlag)
	if cfgErr == nil {
		if host == "" {
			host = cfg.Host
		}
		if token == "" {
			token = cfg.Token
		}
	}
	if host == "" {
		host = "http://127.0.0.1:8777"
	}
	if token == "" {
		if cfgErr != nil {
			return "", "", errors.New("token is required; run racg login, pass --token, or set RACG_TOKEN")
		}
		return "", "", errors.New("token is required; pass --token or set RACG_TOKEN")
	}
	return normalizeClientHost(host), token, nil
}

func loadClientConfigForName(nameFlag string) (clientConfig, error) {
	if strings.TrimSpace(os.Getenv("RACG_CLIENT_CONFIG")) != "" {
		return loadClientConfig()
	}
	name := strings.TrimSpace(nameFlag)
	if name == "" {
		name = strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME"))
	}
	if name == "" {
		name = strings.TrimSpace(os.Getenv("RACG_PROFILE"))
	}
	if name != "" {
		return loadNamedClientConfig(name)
	}
	if active, err := activeClientProfile(); err == nil {
		return loadNamedClientConfig(active)
	}
	return loadClientConfig()
}
