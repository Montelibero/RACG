package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "racg", "racg.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
}

func TestListOpenSessionsHasNoArbitraryLimitAndExcludesEnded(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	started := time.Now().UTC()
	for i := 0; i < 105; i++ {
		id := fmt.Sprintf("session-%03d", i)
		if err := s.InsertSession(ctx, Session{ID: id, StartedAt: started.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatalf("InsertSession %s: %v", id, err)
		}
	}
	if err := s.EndSession(ctx, "session-050", started.Add(time.Hour)); err != nil {
		t.Fatalf("EndSession: %v", err)
	}

	got, err := s.ListOpenSessions(ctx)
	if err != nil {
		t.Fatalf("ListOpenSessions: %v", err)
	}
	if len(got) != 104 {
		t.Fatalf("open sessions=%d, want 104", len(got))
	}
	if got[0].ID != "session-104" {
		t.Fatalf("first session=%q, want newest session-104", got[0].ID)
	}
	for _, sess := range got {
		if sess.ID == "session-050" {
			t.Fatal("ended session returned")
		}
	}
}

func TestMigrateAndSessionCRUD(t *testing.T) {
	ctx := context.Background()

	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	sess := Session{ID: "s1", StartedAt: time.Now().UTC()}
	if err := s.InsertSession(ctx, sess); err != nil {
		t.Fatalf("InsertSession: %v", err)
	}

	got, err := s.GetSession(ctx, "s1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != "s1" {
		t.Fatalf("ID=%q", got.ID)
	}
	if got.EndedAt != nil {
		t.Fatalf("EndedAt expected nil")
	}

	end := time.Now().UTC()
	if err := s.EndSession(ctx, "s1", end); err != nil {
		t.Fatalf("EndSession: %v", err)
	}

	got2, err := s.GetSession(ctx, "s1")
	if err != nil {
		t.Fatalf("GetSession2: %v", err)
	}
	if got2.EndedAt == nil {
		t.Fatalf("EndedAt expected set")
	}
}
