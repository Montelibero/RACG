package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
	"github.com/itolstov/racg/internal/service"
)

func osGetuidString() string { return strconv.Itoa(os.Getuid()) }

func osGetgidString() string { return strconv.Itoa(os.Getgid()) }

type fakeAdminAuthority struct {
	public ed25519.PublicKey
}

func (f *fakeAdminAuthority) ListDevicesTrusted(context.Context) ([]authority.TrustedCredential, error) {
	return []authority.TrustedCredential{{ID: "device", PublicKey: f.public}}, nil
}

func (f *fakeAdminAuthority) RotateDeviceTrusted(context.Context, string, ed25519.PublicKey) error {
	return nil
}

func (f *fakeAdminAuthority) RevokeTrusted(context.Context, string) error { return nil }

func (f *fakeAdminAuthority) ListAgentsTrusted(context.Context) ([]authority.TrustedCredential, error) {
	return []authority.TrustedCredential{}, nil
}

func (f *fakeAdminAuthority) RotateAgentTrusted(context.Context, string, ed25519.PublicKey) error {
	return nil
}

func (f *fakeAdminAuthority) RevokeAgentTrusted(context.Context, string) error { return nil }

func (f *fakeAdminAuthority) ListGrantsTrusted(context.Context) ([]authority.TrustedGrant, error) {
	return []authority.TrustedGrant{}, nil
}

func (f *fakeAdminAuthority) RevokeGrantTrusted(context.Context, string) error { return nil }

func (f *fakeAdminAuthority) IdentityTrusted() (int, string, []byte, error) {
	return 1, "server", append([]byte(nil), f.public...), nil
}

func adminCommandFixture(t *testing.T) (*ServiceAdminCmd, string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := broker.ListenAdminUnix(socket, broker.PeerCredentials{UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.ServeAdminUnix(ctx, listener, broker.PeerCredentials{UID: os.Getuid(), GID: os.Getgid()}, &fakeAdminAuthority{public: public})
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		if err := <-serverDone; err != nil {
			t.Errorf("admin server: %v", err)
		}
	})
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	t.Cleanup(func() {
		t.Logf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	})
	return NewServiceAdminCmd(stdout, stderr), socket
}

func TestServiceAdminExportsVerifiedProfile(t *testing.T) {
	command, socket := adminCommandFixture(t)
	outPath := filepath.Join(t.TempDir(), "server.json")
	code := command.Run([]string{
		"--socket", socket,
		"--admin-uid", osGetuidString(),
		"--admin-gid", osGetgidString(),
		"export-profile", "--out", outPath,
	})
	if code != 0 {
		t.Fatalf("export code=%d", code)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		ServerID  string `json:"server_id"`
		PublicKey []byte `json:"public_key"`
	}
	if err := json.Unmarshal(data, &profile); err != nil || profile.ServerID != "server" || len(profile.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("profile=%s err=%v", data, err)
	}
}

func TestServiceAdminRejectsBadPublicKey(t *testing.T) {
	command, socket := adminCommandFixture(t)
	var out, errOut strings.Builder
	command.stdout = &out
	command.stderr = &errOut
	code := command.Run([]string{
		"--socket", socket,
		"--admin-uid", osGetuidString(),
		"--admin-gid", osGetgidString(),
		"enroll", "device", "--id", "device", "--public-key", "not-base64",
	})
	if code != 2 || !strings.Contains(errOut.String(), "public key invalid") {
		t.Fatalf("code=%d stderr=%q out=%q", code, errOut.String(), out.String())
	}
}
