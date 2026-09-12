package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"crypto/ed25519"

	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// AuthorityService owns the privileged database, signing key and listening
// socket within one process. Close is safe after a failed Open.
type AuthorityService struct {
	listener  *broker.AuthorityUnixListener
	peer      broker.PeerCredentials
	authority *authority.Authority
	db        *sql.DB
	lock      *os.File
}

func OpenAuthority(ctx context.Context, config AuthorityConfig, signingKey ed25519.PrivateKey) (*AuthorityService, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := PrepareAuthorityState(config); err != nil {
		return nil, err
	}
	lock, err := acquireStateLock(config.LockPath())
	if err != nil {
		return nil, err
	}
	service := &AuthorityService{lock: lock}
	db, err := sql.Open("sqlite", config.DatabasePath())
	if err != nil {
		service.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	service.db = db
	service.authority, err = authority.New(ctx, db, config.ServerID, signingKey, nil)
	if err != nil {
		service.Close()
		return nil, err
	}
	service.listener, err = broker.ListenAuthorityUnix(config.SocketPath, broker.PeerCredentials{
		UID: config.BrokerUID,
		GID: config.BrokerGID,
	})
	if err != nil {
		service.Close()
		return nil, err
	}
	service.peer = broker.PeerCredentials{UID: config.BrokerUID, GID: config.BrokerGID}
	return service, nil
}

// Authority is for trusted composition inside the privileged process only.
// It must never be handed to, serialized for, or proxied wholesale to a broker.
func (s *AuthorityService) Authority() *authority.Authority {
	if s == nil {
		return nil
	}
	return s.authority
}

func (s *AuthorityService) Run(ctx context.Context) error {
	if s == nil || s.listener == nil || s.authority == nil {
		return errors.New("authority service is not open")
	}
	err := broker.ServeAuthorityUnix(ctx, s.listener, broker.PeerCredentials{
		UID: s.peer.UID,
		GID: s.peer.GID,
	}, s.authority)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (s *AuthorityService) Close() error {
	var closeErr error
	if s == nil {
		return nil
	}
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			closeErr = err
		}
		s.listener = nil
	}
	if s.db != nil {
		if err := s.db.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		s.db = nil
	}
	if s.lock != nil {
		if err := releaseStateLock(s.lock); err != nil && closeErr == nil {
			closeErr = err
		}
		s.lock = nil
	}
	return closeErr
}

// ConnectBroker prepares broker-only state and opens the peer-verified client.
func ConnectBroker(ctx context.Context, config BrokerConfig) (*broker.AuthorityClient, func(), error) {
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}
	if err := PrepareBrokerState(config); err != nil {
		return nil, nil, err
	}
	client, closeConn, err := broker.DialAuthorityUnix(ctx, config.SocketPath, broker.PeerCredentials{
		UID: config.AuthorityUID,
		GID: config.AuthorityGID,
	})
	if err != nil {
		return nil, nil, err
	}
	return client, closeConn, nil
}

func acquireStateLock(path string) (*os.File, error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("authority state is already in use: %w", err)
	}
	return lock, nil
}

func releaseStateLock(lock *os.File) error {
	err := unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	closeErr := lock.Close()
	if err != nil {
		return err
	}
	return closeErr
}
