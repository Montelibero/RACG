package broker

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func verifyUnixPeer(conn net.Conn, expected PeerCredentials) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("authority transport is not a Unix connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("inspect authority connection: %w", err)
	}
	var credentials *unix.Ucred
	var controlErr error
	controlErr = raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if controlErr != nil {
		return fmt.Errorf("control authority connection: %w", controlErr)
	}
	if err != nil {
		return fmt.Errorf("read peer credentials: %w", err)
	}
	if credentials == nil || int(credentials.Uid) != expected.UID || int(credentials.Gid) != expected.GID {
		return errors.New("authority peer identity mismatch")
	}
	return nil
}
