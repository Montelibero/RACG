package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/approval"
)

type fakeAuthority struct{}

func (fakeAuthority) Submit(context.Context, approval.SignedSubmission) (approval.SignedRequest, error) {
	return approval.SignedRequest{}, errSocketBoundary
}

func (fakeAuthority) LookupSubmission(context.Context, approval.SignedLookup) (approval.SignedLookupResult, error) {
	return approval.SignedLookupResult{}, errSocketBoundary
}

func (fakeAuthority) SubmitDecision(context.Context, string, approval.SignedDecision, []byte) (approval.SignedDecisionReceipt, error) {
	return approval.SignedDecisionReceipt{}, errSocketBoundary
}

func (fakeAuthority) LookupDecision(context.Context, approval.SignedDecisionLookup) (approval.SignedDecisionLookupResult, error) {
	return approval.SignedDecisionLookupResult{}, errSocketBoundary
}

var errSocketBoundary = errSentinel("socket boundary reached")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

func TestListenAuthorityUnixValidatesOwnershipInputs(t *testing.T) {
	temp := t.TempDir()
	for name, tc := range map[string]struct {
		path string
		peer PeerCredentials
	}{
		"relative": {path: "socket", peer: PeerCredentials{UID: 1, GID: 1}},
		"uid":      {path: filepath.Join(temp, "s"), peer: PeerCredentials{UID: -1, GID: 1}},
		"gid":      {path: filepath.Join(temp, "s"), peer: PeerCredentials{UID: 1, GID: -1}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ListenAuthorityUnix(tc.path, tc.peer); err == nil {
				t.Fatal("invalid socket configuration accepted")
			}
		})
	}
}

func TestAuthorityUnixSocketChecksPeersPermissionsAndLifecycle(t *testing.T) {
	// Keep the test's absolute path short enough for Unix-domain socket limits
	// while also validating the transient published socket name.
	directory, err := os.MkdirTemp("/tmp", "racg-socket-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	path := filepath.Join(directory, "authority.sock")
	current := PeerCredentials{UID: os.Getuid(), GID: os.Getgid()}
	listener, err := ListenAuthorityUnix(path, current)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode=%v", got)
	}
	if listener.Path() != path {
		t.Fatalf("listener path=%s", listener.Path())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- ServeAuthorityUnix(ctx, listener, current, fakeAuthority{}) }()

	// A listener's peer credentials are checked before any protocol bytes are
	// sent, so a spoofed expected authority cannot extract agent/device data.
	wrongPeer := PeerCredentials{UID: current.UID, GID: current.GID + 1}
	if _, _, err := DialAuthorityUnix(context.Background(), path, wrongPeer); err == nil {
		t.Fatal("wrong authority identity accepted")
	}

	// Filesystem write permission is a precondition, not authorization.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := DialAuthorityUnix(context.Background(), path, current); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world-writable socket error=%v", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}

	client, closeConn, err := DialAuthorityUnix(context.Background(), path, current)
	if err != nil {
		t.Fatal(err)
	}
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	submission, err := approval.NewSubmission("server", "agent", []byte(`{"type":"cmd.run"}`), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignSubmission(submission, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubmitAgent(context.Background(), signed); err == nil || !strings.Contains(err.Error(), "socket boundary reached") {
		t.Fatalf("boundary error=%v", err)
	}
	closeConn()

	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("socket server did not stop after context cancellation")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket cleanup err=%v", err)
	}
}
