package httpapi

import (
	"bufio"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/itolstov/racg/internal/events"
)

// handleApproverEvents is the instant wake-up channel for phones (item 9.3):
// a WebSocket whose handshake is authenticated exactly like a signed poll
// (poll key or legacy approval key, bound to the exact path). Only the push
// notification rides the socket; the phone still re-reads the pending list
// through the signed REST endpoint, so the socket carries no authority.
func (a *API) handleApproverEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "", "")
		return
	}
	if !websocketUpgradeRequested(r) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "websocket upgrade required", "")
		return
	}
	if err := a.authenticateApproverPoll(r); err != nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error(), "")
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "missing Sec-WebSocket-Key", "")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "connection hijacking unsupported", "")
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	accept := wsAcceptKey(key)
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", accept)
	if err := rw.Flush(); err != nil {
		return
	}

	// Closing the response writer body is not allowed after hijack; drop the
	// connection silently when the context or subscription ends.
	sub, cancel := a.hub.Subscribe(32)
	defer cancel()
	done := make(chan struct{})
	go func() {
		// Drain anything the client sends; a close frame or any read error
		// terminates the session.
		defer close(done)
		buf := make([]byte, 512)
		for {
			if _, err := rw.Read(buf); err != nil {
				return
			}
		}
	}()

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case ev := <-sub:
			if !writeWSFrame(rw, ev) {
				return
			}
		case <-keepalive.C:
			if !writeWSControl(rw, 0x9) { // ping
				return
			}
		case <-done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func websocketUpgradeRequested(r *http.Request) bool {
	return subtle.ConstantTimeCompare(
		[]byte(r.Header.Get("Upgrade")),
		[]byte("websocket"),
	) == 1
}

func wsAcceptKey(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

// writeWSFrame writes a single unmasked text frame carrying the event JSON.
func writeWSFrame(rw *bufio.ReadWriter, ev events.Event) bool {
	payload, err := json.Marshal(ev)
	if err != nil {
		return true // skip undecorable events, keep the socket alive
	}
	return wsWrite(rw, 0x1, payload)
}

func writeWSControl(rw *bufio.ReadWriter, opcode byte) bool {
	return wsWrite(rw, opcode, nil)
}

func wsWrite(rw *bufio.ReadWriter, opcode byte, payload []byte) bool {
	header := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 0xFFFF:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, 127,
			byte(len(payload)>>56), byte(len(payload)>>48), byte(len(payload)>>40), byte(len(payload)>>32),
			byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	}
	if _, err := rw.Write(header); err != nil {
		return false
	}
	if _, err := rw.Write(payload); err != nil {
		return false
	}
	return rw.Flush() == nil
}
