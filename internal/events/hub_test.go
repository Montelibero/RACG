package events

import (
	"testing"
	"time"
)

func TestHubPublishSubscribe(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe(1)
	defer cancel()

	e := Event{Type: "request.created", RequestID: "r1", Ts: time.Unix(1000, 0).UTC()}
	h.Publish(e)

	select {
	case got := <-ch:
		if got.Type != "request.created" {
			t.Fatalf("Type=%q", got.Type)
		}
		if got.RequestID != "r1" {
			t.Fatalf("RequestID=%q", got.RequestID)
		}
	default:
		t.Fatalf("expected event")
	}
}

func TestHubCancelStopsDelivery(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe(1)
	cancel()

	h.Publish(Event{Type: "x"})

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("unexpected event")
		}
	default:
		t.Fatalf("expected closed channel")
	}
}
