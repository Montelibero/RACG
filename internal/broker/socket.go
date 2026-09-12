package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// PeerCredentials names the exact OS identity allowed on the other end. Both
// values are required: filesystem permissions reduce connection attempts, but
// SO_PEERCRED is the actual authority-side authentication boundary.
type PeerCredentials struct {
	UID int
	GID int
}

type UnixSocketConfig struct {
	Path string
	Peer PeerCredentials
}

// AuthorityUnixListener removes the final socket name even though the bound
// socket is atomically renamed from a private temporary name after permissions
// and ownership have been applied.
type AuthorityUnixListener struct {
	*net.UnixListener
	path string
}

func (l *AuthorityUnixListener) Close() error {
	err := l.UnixListener.Close()
	removeErr := os.Remove(l.path)
	if err != nil {
		return err
	}
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return removeErr
	}
	return nil
}

func (l *AuthorityUnixListener) Path() string { return l.path }

func validateUnixSocketConfig(path string, peer PeerCredentials) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("authority socket path must be absolute")
	}
	if filepath.Clean(path) != path {
		return errors.New("authority socket path must be canonical")
	}
	if peer.UID < 0 || peer.GID < 0 {
		return errors.New("peer UID and GID required")
	}
	return nil
}

// ListenAuthorityUnix creates one authority-owned listening socket. The caller
// owns and pre-creates the parent directory with its intended ownership; this
// function deliberately does not discover or mutate a directory hierarchy.
func ListenAuthorityUnix(path string, broker PeerCredentials) (*AuthorityUnixListener, error) {
	if err := validateUnixSocketConfig(path, broker); err != nil {
		return nil, err
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("stat authority socket directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("authority socket parent is not a directory")
	}
	// Eight random bytes are enough to make this transient name unguessable
	// while leaving headroom beneath Unix-domain socket path limits.
	temporary := make([]byte, 8)
	if _, err := rand.Read(temporary); err != nil {
		return nil, err
	}
	temporaryPath := filepath.Join(filepath.Dir(path), ".racg-authority-"+hex.EncodeToString(temporary)+".sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: temporaryPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(temporaryPath, 0o660); err != nil {
		listener.Close()
		return nil, fmt.Errorf("set authority socket permissions: %w", err)
	}
	if err := os.Chown(temporaryPath, os.Getuid(), broker.GID); err != nil {
		listener.Close()
		return nil, fmt.Errorf("set authority socket group: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		listener.Close()
		return nil, fmt.Errorf("publish authority socket: %w", err)
	}
	return &AuthorityUnixListener{UnixListener: listener, path: path}, nil
}

// ServeAuthorityUnix accepts connections until the listener or context closes.
// Each accepted peer is checked before any protocol bytes are read.
func ServeAuthorityUnix(ctx context.Context, listener *AuthorityUnixListener, broker PeerCredentials, authority Authority) error {
	if listener == nil || authority == nil {
		return errors.New("authority listener and service required")
	}
	if err := validateUnixSocketConfig(listener.Path(), broker); err != nil {
		return err
	}
	var workers sync.WaitGroup
	serving := make(chan struct{})
	defer listener.Close()
	defer workers.Wait()
	defer close(serving)
	if done := ctx.Done(); done != nil {
		go func() {
			select {
			case <-done:
				listener.Close()
			case <-serving:
			}
		}()
	}
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			conn.Close()
			return err
		}
		if err := verifyUnixPeer(conn, broker); err != nil {
			conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer conn.Close()
			_ = ServeAuthority(ctx, authority, conn, conn)
		}()
	}
}

// DialAuthorityUnix connects to the configured authority and verifies the
// listener's OS identity before sending protocol bytes.
func DialAuthorityUnix(ctx context.Context, path string, authority PeerCredentials) (*AuthorityClient, func(), error) {
	if err := validateUnixSocketConfig(path, authority); err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat authority socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, nil, errors.New("authority socket path is not a socket")
	}
	if info.Mode().Perm()&0o002 != 0 {
		return nil, nil, errors.New("authority socket is world-writable")
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyUnixPeer(conn, authority); err != nil {
		conn.Close()
		return nil, nil, err
	}
	client, err := NewAuthorityClient(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return client, func() { conn.Close() }, nil
}
