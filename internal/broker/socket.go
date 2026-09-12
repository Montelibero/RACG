package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

// AuthorityUnixListener removes the final socket name even though the bound
// socket is atomically renamed from a private temporary name after permissions
// and ownership have been applied.
type AuthorityUnixListener struct {
	*net.UnixListener
	path string
}

func (l *AuthorityUnixListener) Close() error {
	err := l.UnixListener.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
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

// ListenUnix creates one authority-owned listening socket. The caller
// owns and pre-creates the parent directory with its intended ownership; this
// function deliberately does not discover or mutate a directory hierarchy.
func ListenUnix(path string, peer PeerCredentials, mode os.FileMode) (*AuthorityUnixListener, error) {
	if err := validateUnixSocketConfig(path, peer); err != nil {
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
	temporaryPath := filepath.Join(filepath.Dir(path), ".racg-listener-"+hex.EncodeToString(temporary)+".sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: temporaryPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(temporaryPath, mode); err != nil {
		listener.Close()
		return nil, fmt.Errorf("set authority socket permissions: %w", err)
	}
	if err := os.Chown(temporaryPath, os.Getuid(), peer.GID); err != nil {
		listener.Close()
		return nil, fmt.Errorf("set authority socket group: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		listener.Close()
		return nil, fmt.Errorf("publish authority socket: %w", err)
	}
	return &AuthorityUnixListener{UnixListener: listener, path: path}, nil
}

func ListenAuthorityUnix(path string, peer PeerCredentials) (*AuthorityUnixListener, error) {
	return ListenUnix(path, peer, 0o660)
}

func ListenAdminUnix(path string, peer PeerCredentials) (*AuthorityUnixListener, error) {
	return ListenUnix(path, peer, 0o600)
}

// ServeAuthorityUnix accepts connections until the listener or context closes.
// Each accepted peer is checked before any protocol bytes are read.
func ServeAuthorityUnix(ctx context.Context, listener *AuthorityUnixListener, broker PeerCredentials, authority Authority) error {
	if listener == nil || authority == nil {
		return errors.New("authority listener and service required")
	}
	return ServeUnix(ctx, listener, broker, func(ctx context.Context, conn io.ReadWriter) error {
		return ServeAuthority(ctx, authority, conn, conn)
	})
}

// ConnHandler serves one already peer-authenticated Unix connection.
type ConnHandler func(context.Context, io.ReadWriter) error

// ServeUnix accepts connections until listener/context close. It is shared by
// broker and trusted-admin protocols; each caller supplies the protocol handler.
func ServeUnix(ctx context.Context, listener *AuthorityUnixListener, peer PeerCredentials, handler ConnHandler) error {
	if listener == nil || handler == nil {
		return errors.New("socket listener and handler required")
	}
	if err := validateUnixSocketConfig(listener.Path(), peer); err != nil {
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
		if err := VerifyUnixPeer(conn, peer); err != nil {
			conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer conn.Close()
			_ = handler(ctx, conn)
		}()
	}
}

// DialUnix verifies the listener peer before exposing a generic connection.
func DialUnix(ctx context.Context, path string, peer PeerCredentials) (*net.UnixConn, func(), error) {
	if err := validateUnixSocketConfig(path, peer); err != nil {
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
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		unixConn.Close()
		return nil, nil, errors.New("authority transport is not Unix")
	}
	if err := VerifyUnixPeer(unixConn, peer); err != nil {
		unixConn.Close()
		return nil, nil, err
	}
	return unixConn, func() { unixConn.Close() }, nil
}

// DialAuthorityUnix connects to the configured authority and verifies the
// listener's OS identity before sending protocol bytes.
func DialAuthorityUnix(ctx context.Context, path string, authority PeerCredentials) (*AuthorityClient, func(), error) {
	conn, closeConn, err := DialUnix(ctx, path, authority)
	if err != nil {
		return nil, nil, err
	}
	client, err := NewAuthorityClient(conn)
	if err != nil {
		closeConn()
		return nil, nil, err
	}
	return client, closeConn, nil
}
