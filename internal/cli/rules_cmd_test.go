package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

func TestCLIRulesListAndDisable(t *testing.T) {
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
	if err := st.InsertAlwaysRule(ctx, rules.Rule{
		ID:     "allow-echo",
		OpType: "cmd.run",
		Cmd:    &rules.CmdRule{ArgvPrefix: []string{"/bin/echo"}},
	}, time.Now().UTC()); err != nil {
		t.Fatalf("InsertAlwaysRule: %v", err)
	}
	_ = st.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)

	if code := root.Run([]string{"rules", "list", "--db", dbPath}); code != 0 {
		t.Fatalf("rules list code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "allow-echo") {
		t.Fatalf("stdout=%q", out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := root.Run([]string{"rules", "disable", "allow-echo", "--db", dbPath}); code != 0 {
		t.Fatalf("rules disable code=%d stderr=%s", code, errOut.String())
	}

	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open2: %v", err)
	}
	defer st2.Close()
	if enabled, err := st2.LoadEnabledAlwaysRules(ctx); err != nil {
		t.Fatalf("LoadEnabledAlwaysRules: %v", err)
	} else if len(enabled) != 0 {
		t.Fatalf("enabled len=%d", len(enabled))
	}
}

