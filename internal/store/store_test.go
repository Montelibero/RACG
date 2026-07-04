package store

import (
	"context"
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
