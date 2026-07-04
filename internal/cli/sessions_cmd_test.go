package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/store"
)

func TestCLISessionsListAndShow(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "racg.db")

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}
	if err := st.InsertSession(ctx, store.Session{ID: "sess1", StartedAt: time.Unix(1000, 0).UTC()}); err != nil {
		t.Fatalf("InsertSession: %v", err)
	}
	_ = st.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)

	if code := root.Run([]string{"sessions", "list", "--db", dbPath}); code != 0 {
		t.Fatalf("sessions list code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "sess1") {
		t.Fatalf("stdout=%q", out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := root.Run([]string{"sessions", "show", "sess1", "--db", dbPath}); code != 0 {
		t.Fatalf("sessions show code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "sess1") {
		t.Fatalf("stdout=%q", out.String())
	}
}
