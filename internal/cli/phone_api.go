package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/itolstov/racg/internal/approvalbridge"
)

type phoneHandler struct {
	bridge *approvalbridge.Client
	phone  *approvalbridge.PhoneServer

	mu         sync.Mutex
	challenges map[string]time.Time
}

func (h *phoneHandler) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pair", h.pair)
	mux.HandleFunc("/v1/challenge", h.challenge)
	mux.HandleFunc("/v1/challenge", h.challenge)
	mux.HandleFunc("/v1/requests", h.requests)
	mux.HandleFunc("/v1/request", h.request)
	mux.HandleFunc("/v1/decision", h.decision)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (h *phoneHandler) pair(w http.ResponseWriter, r *http.Request) {
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
	if err := h.phone.Pair(input.Code, input.DeviceID, input.PublicKey); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := h.bridge.Pair(input.Code, input.DeviceID, input.PublicKey); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	writeJSONPhone(w, map[string]any{"ok": true, "device_id": input.DeviceID})
}

func (h *phoneHandler) challenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	challenge, err := h.bridge.Challenge()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	h.mu.Lock()
	h.challenges[challenge] = time.Now().Add(2 * time.Minute)
	h.mu.Unlock()
	writeJSONPhone(w, map[string]any{"challenge": challenge})
}

func (h *phoneHandler) requests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requests, err := h.bridge.Pending()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSONPhone(w, map[string]any{"requests": requests})
}

func (h *phoneHandler) request(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestID := r.URL.Query().Get("id")
	request, err := h.bridge.Request(requestID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSONPhone(w, request)
}

type phoneDecisionInput struct {
	DeviceID  string `json:"device_id"`
	RequestID string `json:"request_id"`
	Decision  string `json:"decision"`
	OpSHA256  string `json:"op_sha256"`
	Challenge string `json:"challenge"`
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
}

func (h *phoneHandler) decision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input phoneDecisionInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid decision", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	expiry, ok := h.challenges[input.Challenge]
	h.mu.Unlock()
	if !ok || time.Now().After(expiry) {
		http.Error(w, "challenge expired", http.StatusUnauthorized)
		return
	}
	decision := approvalbridge.PhoneDecision{
		DeviceID:  input.DeviceID,
		RequestID: input.RequestID,
		Decision:  input.Decision,
		OpSHA256:  input.OpSHA256,
		Challenge: input.Challenge,
		PublicKey: input.PublicKey,
		Signature: input.Signature,
	}
	if err := h.bridge.Decide(decision); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	h.mu.Lock()
	delete(h.challenges, input.Challenge)
	h.mu.Unlock()
	writeJSONPhone(w, map[string]any{"ok": true})
}

func writeJSONPhone(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
