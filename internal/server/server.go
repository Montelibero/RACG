package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/itolstov/racg/internal/auth"
	"github.com/itolstov/racg/internal/config"
	"github.com/itolstov/racg/internal/httpapi"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

type Server struct {
	cfg        config.Config
	httpServer *http.Server
	handler    http.Handler
	ln         net.Listener
	api        *httpapi.API
	st         *store.Store
	tm         *auth.TokenManager
}

func New(cfg config.Config) (*Server, error) {
	if cfg.ListenAddr == "" && cfg.SocketPath == "" {
		return nil, fmt.Errorf("listen_addr or socket is required")
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", cfg.Port)
	}
	if cfg.MaxConcurrency <= 0 {
		return nil, fmt.Errorf("max_concurrency must be > 0")
	}
	// MVP: always use SQLite for audit/rules persistence.
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("store open: %w", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("store migrate: %w", err)
	}

	re := rules.NewEngine()
	if always, err := st.LoadEnabledAlwaysRules(context.Background()); err == nil {
		for _, r := range always {
			re.AddAlways(r)
		}
	} else {
		_ = st.Close()
		return nil, fmt.Errorf("store load always rules: %w", err)
	}

	// Auth tokens survive restarts: replay persisted records into the
	// manager and mirror every change back through its OnChange sink.
	tm := auth.NewTokenManager(auth.RealClock{})
	tokens, err := st.ListAuthTokens(context.Background())
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("store load auth tokens: %w", err)
	}
	for _, t := range tokens {
		tm.Restore(t.TokenHash, auth.Claims{SessionID: t.SessionID, ClientID: t.ClientID, ExpiresAt: t.ExpiresAt})
	}
	tm.OnChange(func(hash string, claims auth.Claims, deleted bool) {
		// Persistence failures are non-fatal (MVP): the in-memory
		// token keeps working; only restart durability is lost.
		ctx := context.Background()
		if deleted {
			_ = st.DeleteAuthToken(ctx, hash)
			return
		}
		_ = st.UpsertAuthToken(ctx, hash, claims.SessionID, claims.ClientID, claims.ExpiresAt)
	})

	api := httpapi.New(cfg, httpapi.WithRulesEngine(re), httpapi.WithStore(st), httpapi.WithTokenManager(tm))
	if err := api.RehydrateFromStore(context.Background()); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("store rehydrate: %w", err)
	}
	handler := api.Handler()

	return &Server{
		cfg: cfg,
		httpServer: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
		},
		handler: handler,
		api:     api,
		st:      st,
		tm:      tm,
	}, nil
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *Server) PairingCode() string {
	return s.api.PairingCode()
}

func (s *Server) API() *httpapi.API { return s.api }

// Tokens exposes the session token manager (e.g. for logout/revoke).
func (s *Server) Tokens() *auth.TokenManager { return s.tm }

func (s *Server) Store() *store.Store { return s.st }

func (s *Server) Run(ctx context.Context, ready chan<- struct{}) error {
	if s.st != nil {
		defer func() { _ = s.st.Close() }()
	}

	var ln net.Listener
	var err error
	if s.cfg.SocketPath != "" {
		// Privileged pipeline mode: the only listener is a permission-
		// restricted unix socket; the facade connects here, the network does not.
		ln, err = net.Listen("unix", s.cfg.SocketPath)
		if err == nil {
			if err := os.Chmod(s.cfg.SocketPath, 0o660); err != nil {
				_ = ln.Close()
				return err
			}
		}
	} else {
		addr := net.JoinHostPort(s.cfg.ListenAddr, strconv.Itoa(s.cfg.Port))
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return err
	}
	s.ln = ln
	close(ready)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
		err := <-errCh
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
