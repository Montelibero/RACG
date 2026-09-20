package approvalbridge

import (
	"context"
	"crypto/ecdsa"
	crypto_rand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/itolstov/racg/internal/httpapi"
)

type Backend interface {
	PendingForPhone() []httpapi.PhoneRequest
	RequestForPhone(requestID string) (httpapi.PhoneRequest, bool)
	DecideForPhone(requestID, decision, deviceID string) error
}

type Server struct {
	backend Backend
	devices *DeviceRegistry

	mu         sync.Mutex
	challenges map[string]time.Time
}

func NewServer(backend Backend, devices *DeviceRegistry) *Server {
	return &Server{backend: backend, devices: devices, challenges: map[string]time.Time{}}
}

func Serve(ctx context.Context, socketPath string, server *Server) error {
	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		listener.Close()
		return err
	}

	srv := &http.Server{Handler: server.routes(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(listener) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		listener.Close()
		err := <-errCh
		_ = os.Remove(socketPath)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-errCh:
		return err
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pending", s.handlePending)
	mux.HandleFunc("/v1/request", s.handleRequest)
	mux.HandleFunc("/v1/decision", s.handleDecision)
	mux.HandleFunc("/v1/pair", s.handlePair)
	mux.HandleFunc("/v1/challenge", s.issueChallenge)
	return mux
}

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"requests": s.backend.PendingForPhone()})
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestID := r.URL.Query().Get("id")
	request, ok := s.backend.RequestForPhone(requestID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, request)
}

type decisionRequest struct {
	PhoneDecision
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input decisionRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid decision", http.StatusBadRequest)
		return
	}
	if input.Decision != "ALLOW_ONCE" && input.Decision != "DENY" {
		http.Error(w, "invalid decision action", http.StatusBadRequest)
		return
	}
	publicKey, err := s.devices.PublicKey(input.DeviceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	message := DecisionMessage(input.DeviceID, input.RequestID, input.Decision, input.OpSHA256, input.Challenge)
	if err := verifyPhoneDecisionSignature(publicKey, message, input.Signature); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	request, ok := s.backend.RequestForPhone(input.RequestID)
	if !ok || request.OpSHA256 != input.OpSHA256 {
		http.Error(w, "request digest mismatch", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	expiry, ok := s.challenges[input.Challenge]
	delete(s.challenges, input.Challenge)
	s.mu.Unlock()
	if !ok || time.Now().After(expiry) || subtle.ConstantTimeCompare([]byte(input.Challenge), []byte(input.Challenge)) != 1 {
		http.Error(w, "challenge expired", http.StatusUnauthorized)
		return
	}
	if err := s.backend.DecideForPhone(input.RequestID, input.Decision, input.DeviceID); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Code      string `json:"code"`
		DeviceID  string `json:"device_id"`
		PublicKey []byte `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid pairing request", http.StatusBadRequest)
		return
	}
	if err := s.devices.Pair(input.Code, input.DeviceID, input.PublicKey); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "device_id": input.DeviceID})
}

func (s *Server) issueChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	challenge := randomToken()
	s.mu.Lock()
	s.challenges[challenge] = time.Now().Add(2 * time.Minute)
	s.mu.Unlock()
	for key, expiry := range s.challenges {
		if time.Now().After(expiry) {
			delete(s.challenges, key)
		}
	}
	writeJSON(w, map[string]any{"challenge": challenge})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func randomToken() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

func randomBytes(length int) []byte {
	b := make([]byte, length)
	if _, err := crypto_rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

var _ = fmt.Sprintf
var _ = hex.EncodeToString
var _ = ecdsa.Verify
