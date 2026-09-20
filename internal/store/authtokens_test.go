package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthTokensCRUD(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "racg.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	exp := time.Unix(2000, 123456789).UTC()
	if err := s.UpsertAuthToken(ctx, "hash1", "sess1", "client1", exp); err != nil {
		t.Fatalf("UpsertAuthToken: %v", err)
	}
	if err := s.UpsertAuthToken(ctx, "hash2", "sess1", "client2", time.Time{}); err != nil {
		t.Fatalf("UpsertAuthToken no-expiry: %v", err)
	}
	// Upsert on the same hash updates in place instead of duplicating.
	if err := s.UpsertAuthToken(ctx, "hash1", "sess1", "client1", exp.Add(time.Minute)); err != nil {
		t.Fatalf("UpsertAuthToken update: %v", err)
	}

	got, err := s.ListAuthTokens(ctx)
	if err != nil {
		t.Fatalf("ListAuthTokens: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("tokens=%d, want 2", len(got))
	}
	byHash := map[string]AuthToken{}
	for _, tok := range got {
		byHash[tok.TokenHash] = tok
	}
	h1, ok := byHash["hash1"]
	if !ok {
		t.Fatalf("hash1 missing: %+v", got)
	}
	if h1.SessionID != "sess1" || h1.ClientID != "client1" {
		t.Fatalf("hash1 = %+v", h1)
	}
	if !h1.ExpiresAt.Equal(exp.Add(time.Minute)) {
		t.Fatalf("hash1 expires=%v, want %v", h1.ExpiresAt, exp.Add(time.Minute))
	}
	h2, ok := byHash["hash2"]
	if !ok {
		t.Fatalf("hash2 missing: %+v", got)
	}
	if !h2.ExpiresAt.IsZero() {
		t.Fatalf("hash2 expires=%v, want zero", h2.ExpiresAt)
	}

	if err := s.DeleteAuthToken(ctx, "hash1"); err != nil {
		t.Fatalf("DeleteAuthToken: %v", err)
	}
	got, err = s.ListAuthTokens(ctx)
	if err != nil {
		t.Fatalf("ListAuthTokens: %v", err)
	}
	if len(got) != 1 || got[0].TokenHash != "hash2" {
		t.Fatalf("tokens=%+v, want only hash2", got)
	}

	if err := s.DeleteAuthTokensBySession(ctx, "sess1"); err != nil {
		t.Fatalf("DeleteAuthTokensBySession: %v", err)
	}
	got, err = s.ListAuthTokens(ctx)
	if err != nil {
		t.Fatalf("ListAuthTokens: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("tokens=%+v, want empty", got)
	}
}
