package server

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/config"
)

type Server struct {
	cfg        config.Config
	httpServer *http.Server
	handler    http.Handler
	ln         net.Listener
	pairing    string
}

func New(cfg config.Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listen_addr is required")
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", cfg.Port)
	}
	if cfg.MaxConcurrency <= 0 {
		return nil, fmt.Errorf("max_concurrency must be > 0")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return &Server{
		cfg: cfg,
		httpServer: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		handler: mux,
		pairing: generatePairingCode(6),
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
	return s.pairing
}

func (s *Server) Run(ctx context.Context, ready chan<- struct{}) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
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

func generatePairingCode(n int) string {
	if n <= 0 {
		n = 6
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "AAAAAA"[:n]
	}
	// base32 without padding, then take first n chars.
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	s = strings.TrimRight(s, "=")
	s = strings.ToUpper(s)
	if len(s) < n {
		return s
	}
	return s[:n]
}
