//go:build !linux

package broker

import (
	"errors"
	"net"
)

func VerifyUnixPeer(net.Conn, PeerCredentials) error {
	return errors.New("peer-credential verification is Linux-only")
}
