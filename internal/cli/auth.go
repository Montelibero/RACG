package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type AuthCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewAuthCmd(stdout, stderr io.Writer) *AuthCmd {
	return &AuthCmd{stdout: stdout, stderr: stderr}
}

func (c *AuthCmd) RunLogin(args []string) int {
	fs := flag.NewFlagSet("racg login", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	host := fs.String("host", envOrDefault("RACG_HOST", "http://127.0.0.1:8777"), "RACG server URL")
	pairingCode := fs.String("pairing-code", "", "pairing code from racg serve TUI")
	clientID := fs.String("client-id", envOrDefault("RACG_CLIENT_ID", "racg-cli"), "client id")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name; defaults to host-derived name")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	code := strings.TrimSpace(*pairingCode)
	if code == "" {
		fmt.Fprint(c.stderr, "pairing code: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			fmt.Fprintf(c.stderr, "failed to read pairing code: %v\n", err)
			return 1
		}
		code = strings.TrimSpace(line)
	}
	if code == "" {
		fmt.Fprintln(c.stderr, "pairing code is required")
		return 2
	}

	h := normalizeClientHost(*host)
	if h == "" {
		fmt.Fprintln(c.stderr, "host is required")
		return 2
	}
	resp, err := openSession(h, strings.TrimSpace(*clientID), code)
	if err != nil {
		fmt.Fprintf(c.stderr, "login failed: %v\n", err)
		return 1
	}
	profile := sanitizeClientProfileName(*name)
	if profile == "" {
		profile = autoClientProfileName(h)
	}
	configPath, err := saveNamedClientConfig(profile, clientConfig{
		Host:      h,
		Token:     resp.SessionToken,
		SessionID: resp.SessionID,
		ClientID:  strings.TrimSpace(*clientID),
		ExpiresAt: resp.ExpiresAt,
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "config save failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "logged_in=true\nprofile: %s\nhost: %s\nsession_id: %s\nexpires_at: %s\nconfig_path: %s\n", profile, h, resp.SessionID, resp.ExpiresAt, configPath)
	fmt.Fprintf(c.stdout, "hint: use --name %s to target this server explicitly, or racg use %s to make it active\n", profile, profile)
	return 0
}

func (c *AuthCmd) RunLogout(args []string) int {
	fs := flag.NewFlagSet("racg logout", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := removeClientConfig(); err != nil {
		fmt.Fprintf(c.stderr, "logout failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(c.stdout, "logged_out=true")
	return 0
}

func (c *AuthCmd) RunSession(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: racg session <status>")
		return 2
	}
	switch args[0] {
	case "status":
		return c.runSessionStatus(args[1:])
	default:
		fmt.Fprintln(c.stderr, "usage: racg session <status>")
		return 2
	}
}

func (c *AuthCmd) RunUse(args []string) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(c.stderr, "usage: racg use <profile_name>")
		return 2
	}
	name := sanitizeClientProfileName(args[0])
	cfg, err := loadNamedClientConfig(name)
	if err != nil {
		fmt.Fprintf(c.stderr, "profile not found: %v\n", err)
		return 1
	}
	if err := setActiveClientProfile(name); err != nil {
		fmt.Fprintf(c.stderr, "use failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "active_profile: %s\nhost: %s\n", name, cfg.Host)
	return 0
}

func (c *AuthCmd) runSessionStatus(args []string) int {
	fs := flag.NewFlagSet("racg session status", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	h, tok, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client, err := newRACGClient(h, tok)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	me, err := client.sessionMe()
	if err != nil {
		fmt.Fprintf(c.stderr, "session status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "host: %s\nsession_id: %s\nclient_id: %s\nexpires_at: %s\nprivilege_mode: %s\n", h, me.SessionID, me.ClientID, me.ExpiresAt, me.PrivilegeMode)
	return 0
}

type sessionOpenResp struct {
	SessionID    string `json:"session_id"`
	SessionToken string `json:"session_token"`
	ExpiresAt    string `json:"expires_at"`
}

func openSession(host string, clientID string, pairingCode string) (sessionOpenResp, error) {
	body, err := json.Marshal(map[string]string{
		"client_id":    clientID,
		"pairing_code": pairingCode,
	})
	if err != nil {
		return sessionOpenResp{}, err
	}
	req, err := http.NewRequest(http.MethodPost, host+"/v1/session/open", bytes.NewReader(body))
	if err != nil {
		return sessionOpenResp{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sessionOpenResp{}, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return sessionOpenResp{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return sessionOpenResp{}, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out sessionOpenResp
	if err := json.Unmarshal(respBody, &out); err != nil {
		return sessionOpenResp{}, err
	}
	if out.SessionToken == "" {
		return sessionOpenResp{}, fmt.Errorf("server response missing session_token")
	}
	return out, nil
}
