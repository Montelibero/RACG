package tui

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/events"
)

func TestUIEventCoalescerKeepsOneDirtySignalAndLatestCreatedEvent(t *testing.T) {
	c := newUIEventCoalescer()
	for i := 0; i < 1000; i++ {
		c.Add(events.Event{Type: "request.output", RequestID: "job"})
	}
	c.Add(events.Event{Type: "request.created", RequestID: "old", ClientID: "client-old"})
	c.Add(events.Event{Type: "request.created", RequestID: "new", ClientID: "client-new"})

	if got := len(c.signal); got != 1 {
		t.Fatalf("dirty signals=%d want 1", got)
	}
	batch, ok := c.Take()
	if !ok {
		t.Fatal("expected dirty batch")
	}
	if batch.LatestCreated == nil || batch.LatestCreated.RequestID != "new" {
		t.Fatalf("latest created=%+v", batch.LatestCreated)
	}
	if _, ok := c.Take(); ok {
		t.Fatal("batch remained dirty after Take")
	}
}

func TestInputEventIsStale(t *testing.T) {
	now := time.Now()
	if !inputEventIsStale(now.Add(-3*time.Second), now, 2*time.Second) {
		t.Fatal("old input was not stale")
	}
	if inputEventIsStale(now.Add(-time.Second), now, 2*time.Second) {
		t.Fatal("fresh input was stale")
	}
	if inputEventIsStale(time.Time{}, now, 2*time.Second) {
		t.Fatal("zero event time must be accepted")
	}
}

func TestDecisionGuardIgnoresRepeatedActionWhileFirstIsInFlight(t *testing.T) {
	s := newUIState(nil, nil)
	s.selectedPending = "req-1"
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	s.decisionRunner = func(requestID, decision string) error {
		calls.Add(1)
		if requestID != "req-1" || decision != "ALLOW_ONCE" {
			t.Errorf("decision request=%q decision=%q", requestID, decision)
		}
		close(started)
		<-release
		return nil
	}
	queued := make(chan func(), 1)
	queue := func(f func()) { queued <- f }

	if !s.tryStartDecision("ALLOW_ONCE", queue) {
		t.Fatal("first decision did not start")
	}
	<-started
	s.selectedPending = "req-2"
	if s.tryStartDecision("ALLOW_ONCE", queue) {
		t.Fatal("repeated decision started while first was in flight")
	}
	close(release)
	completion := <-queued
	completion()

	if s.decisionInFlight {
		t.Fatal("decision remained in flight")
	}
	if s.selectedPending != "req-2" {
		t.Fatalf("completion cleared newer selection %q", s.selectedPending)
	}
	if s.tryStartDecision("ALLOW_ONCE", queue) {
		t.Fatal("repeated decision started during the stale-input guard interval")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("decision calls=%d want 1", got)
	}
}
