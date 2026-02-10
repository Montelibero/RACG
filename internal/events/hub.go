package events

import (
	"sync"
	"time"
)

type Event struct {
	Type      string         `json:"type"`
	Ts        time.Time      `json:"ts"`
	RequestID string         `json:"request_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	ClientID  string         `json:"client_id,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

type Hub struct {
	mu     sync.Mutex
	nextID int
	subs   map[int]chan Event
}

func NewHub() *Hub {
	return &Hub{subs: map[int]chan Event{}}
}

func (h *Hub) Subscribe(buf int) (<-chan Event, func()) {
	if buf <= 0 {
		buf = 1
	}
	ch := make(chan Event, buf)

	h.mu.Lock()
	id := h.nextID
	h.nextID++
	h.subs[id] = ch
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		c, ok := h.subs[id]
		if ok {
			delete(h.subs, id)
		}
		h.mu.Unlock()
		if ok {
			close(c)
		}
	}

	return ch, cancel
}

func (h *Hub) Publish(e Event) {
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.subs {
		select {
		case ch <- e:
		default:
			// Drop if subscriber is slow.
		}
	}
}
