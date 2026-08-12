package tui

import (
	"sync"
	"time"

	"github.com/itolstov/racg/internal/events"
)

const (
	uiRefreshInterval = 250 * time.Millisecond
	maxInputEventAge  = 2 * time.Second
)

type uiEventBatch struct {
	LatestCreated *events.Event
}

type uiEventCoalescer struct {
	mu            sync.Mutex
	signal        chan struct{}
	latestCreated *events.Event
}

func newUIEventCoalescer() *uiEventCoalescer {
	return &uiEventCoalescer{signal: make(chan struct{}, 1)}
}

func (c *uiEventCoalescer) Add(event events.Event) {
	c.mu.Lock()
	if event.Type == "request.created" {
		copy := event
		c.latestCreated = &copy
	}
	c.mu.Unlock()

	select {
	case c.signal <- struct{}{}:
	default:
	}
}

func (c *uiEventCoalescer) Take() (uiEventBatch, bool) {
	select {
	case <-c.signal:
	default:
		return uiEventBatch{}, false
	}

	c.mu.Lock()
	batch := uiEventBatch{LatestCreated: c.latestCreated}
	c.latestCreated = nil
	c.mu.Unlock()
	return batch, true
}

func inputEventIsStale(eventTime, now time.Time, maxAge time.Duration) bool {
	return !eventTime.IsZero() && maxAge > 0 && now.Sub(eventTime) > maxAge
}
