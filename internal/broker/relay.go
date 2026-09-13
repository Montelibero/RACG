package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
)

// Relay is an unprivileged protocol forwarder. It has no authority key and no
// authorization power: every message remains signed and verified by its sender
// and the authority.
type Relay struct {
	URI            string
	AuthorityPath  string
	AuthorityPeer  PeerCredentials
	ListenGroupGID int

	listener net.Listener
}

func ParseListenerURI(value string) (string, string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", "", err
	}
	if !parsed.IsAbs() {
		return "", "", errors.New("listener must be an absolute tcp:// or unix:// URI")
	}
	switch parsed.Scheme {
	case "tcp", "tcp4", "tcp6":
		if parsed.Host == "" {
			return "", "", errors.New("tcp listener requires host and port")
		}
		if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
			return "", "", fmt.Errorf("tcp listener requires host and port: %w", err)
		}
		if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", "", errors.New("tcp listener accepts host and port only")
		}
		return parsed.Scheme, parsed.Host, nil
	case "unix":
		if parsed.Path == "" {
			return "", "", errors.New("unix listener requires a socket path")
		}
		if parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", "", errors.New("unix listener accepts a socket path only")
		}
		return "unix", parsed.Path, nil
	default:
		return "", "", fmt.Errorf("unsupported listener scheme %q", parsed.Scheme)
	}
}

func (r *Relay) Listen() error {
	if r == nil || r.AuthorityPath == "" {
		return errors.New("authority socket required")
	}
	if r.listener != nil {
		return nil
	}
	network, address, err := ParseListenerURI(r.URI)
	if err != nil {
		return err
	}
	if network == "unix" {
		groupID := r.ListenGroupGID
		if groupID < 0 {
			groupID = os.Getegid()
		}
		listener, err := ListenUnix(address, PeerCredentials{UID: os.Getuid(), GID: groupID}, 0o660)
		if err != nil {
			return err
		}
		r.listener = listener
		return nil
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	r.listener = listener
	return nil
}

func (r *Relay) Addr() net.Addr {
	if r == nil || r.listener == nil {
		return nil
	}
	return r.listener.Addr()
}

func (r *Relay) Serve(ctx context.Context) error {
	if r == nil || r.listener == nil {
		return errors.New("relay listener is not open")
	}
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			conn.Close()
			return ctx.Err()
		}
		go r.serveConn(ctx, conn)
	}
}

func (r *Relay) Close() error {
	if r == nil || r.listener == nil {
		return nil
	}
	return r.listener.Close()
}

func (r *Relay) serveConn(ctx context.Context, inbound net.Conn) {
	defer inbound.Close()
	authority, closeAuthority, err := DialUnix(ctx, r.AuthorityPath, r.AuthorityPeer)
	if err != nil {
		return
	}
	defer closeAuthority()
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyBuffer(writeOnlyWriter{w: authority}, inbound, make([]byte, 32*1024))
		done <- err
	}()
	_, _ = io.CopyBuffer(writeOnlyWriter{w: inbound}, authority, make([]byte, 32*1024))
	<-done
}

// writeOnlyWriter prevents io.Copy's Linux ReadFrom optimization, which can
// remain in splice even after the source connection is closed by another path.
type writeOnlyWriter struct {
	w io.Writer
}

func (w writeOnlyWriter) Write(p []byte) (int, error) { return w.w.Write(p) }
