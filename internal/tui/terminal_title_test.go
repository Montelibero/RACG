package tui

import (
	"context"
	"testing"
	"time"
)

func TestTerminalTitleUpdaterDoesNotBlockProducerAndCoalesces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan string, 2)
	releaseFirst := make(chan struct{})
	calls := 0
	updater := newTerminalTitleUpdater(ctx, 75*time.Millisecond, func(title string) {
		calls++
		started <- title
		if calls == 1 {
			<-releaseFirst
		}
	})

	updater.Update("frame-1")
	if got := <-started; got != "frame-1" {
		t.Fatalf("first title=%q", got)
	}

	done := make(chan struct{})
	go func() {
		updater.Update("frame-2")
		updater.Update("frame-3")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("title update blocked while terminal writer was slow")
	}

	close(releaseFirst)
	select {
	case got := <-started:
		t.Fatalf("next title started without cooldown: %q", got)
	case <-time.After(25 * time.Millisecond):
	}
	select {
	case got := <-started:
		if got != "frame-3" {
			t.Fatalf("coalesced title=%q, want frame-3", got)
		}
	case <-time.After(time.Second):
		t.Fatal("coalesced title was not delivered")
	}
}
