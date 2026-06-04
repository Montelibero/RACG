package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	host = strings.TrimSpace(hostFlag)
	token = strings.TrimSpace(tokenFlag)
	if host != "" && token != "" {
		return strings.TrimRight(host, "/"), token, nil
	}
	cfg, cfgErr := loadClientConfig()
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
	return strings.TrimRight(host, "/"), token, nil
}
