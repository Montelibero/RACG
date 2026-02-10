package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/itolstov/racg/internal/config"
)

func TestServerHealthzHandler(t *testing.T) {
	cfg := config.Defaults()

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example/healthz", nil)
	rw := httptest.NewRecorder()
	s.Handler().ServeHTTP(rw, req)

	if rw.Code != 200 {
		t.Fatalf("status=%d", rw.Code)
	}
	if rw.Body.String() != "ok" {
		t.Fatalf("body=%q", rw.Body.String())
	}

	if got := len(s.PairingCode()); got != 6 {
		t.Fatalf("pairing len=%d", got)
	}
}
