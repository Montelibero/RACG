package service

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/itolstov/racg/internal/authority"
	"github.com/itolstov/racg/internal/broker"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// AuthorityService owns the privileged database, signing key and listening
// socket within one process. Close is safe after a failed Open.
type AuthorityService struct {
	listener      *broker.AuthorityUnixListener
	adminListener *broker.AuthorityUnixListener
	peer          broker.PeerCredentials
	adminPeer     broker.PeerCredentials
	authority     *authority.Authority
	executions    *executionSupervisor
	db            *sql.DB
	lock          *os.File
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
	if len(signingKey) == 0 {
		signingKey, err = LoadOrCreateAuthoritySigningKey(config.PrivateKeyPath())
		if err != nil {
			service := &AuthorityService{lock: lock}
			service.Close()
			return nil, err
		}
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
	// Startup owns the state exclusively. Interrupted EXECUTING requests become
	// UNCERTAIN before any socket accepts traffic and are never rerun.
	if _, err := service.authority.RecoverInterruptedTrusted(ctx); err != nil {
		service.Close()
		return nil, err
	}
	service.executions = newExecutionSupervisor(service.authority, config.Execution.Options())
	service.listener, err = broker.ListenAuthorityUnix(config.SocketPath, broker.PeerCredentials{
		UID: config.BrokerUID,
		GID: config.BrokerGID,
	})
	if err != nil {
		service.Close()
		return nil, err
	}
	service.peer = broker.PeerCredentials{UID: config.BrokerUID, GID: config.BrokerGID}
	service.adminListener, err = broker.ListenAdminUnix(config.AdminSocket, broker.PeerCredentials{
		UID: config.AdminUID,
		GID: config.AdminGID,
	})
	if err != nil {
		service.Close()
		return nil, err
	}
	service.adminPeer = broker.PeerCredentials{UID: config.AdminUID, GID: config.AdminGID}
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

// PublicKey exposes the pinned authority identity to trusted composition for
// local clients; the signing key never leaves the service.
func (s *AuthorityService) PublicKey() ed25519.PublicKey {
	if s == nil || s.authority == nil {
		return nil
	}
	return s.authority.PublicKey()
}

func (s *AuthorityService) Run(ctx context.Context) error {
	if s == nil || s.listener == nil || s.adminListener == nil || s.executions == nil {
		return errors.New("authority service is not open")
	}
	results := make(chan error, 2)
	go func() {
		results <- broker.ServeAuthorityUnix(ctx, s.listener, s.peer, s.executions)
	}()
	go func() {
		results <- ServeAdminUnix(ctx, s.adminListener, s.adminPeer, s.authority)
	}()
	var first error
	for i := 0; i < 2; i++ {
		err := <-results
		if first == nil {
			first = err
		}
		if first != nil {
			s.closeListeners()
		}
	}
	if errors.Is(first, context.Canceled) {
		return nil
	}
	return first
}

func (s *AuthorityService) closeListeners() {
	if s == nil {
		return
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.adminListener != nil {
		_ = s.adminListener.Close()
	}
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
	if s.adminListener != nil {
		if err := s.adminListener.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		s.adminListener = nil
	}
	if s.executions != nil {
		if err := s.executions.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		s.executions = nil
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
	config = config.Normalized()
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}
	config = config.Normalized()
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
