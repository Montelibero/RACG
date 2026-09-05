package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/itolstov/racg/internal/rules"
)

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

var ErrRequestNotPending = errors.New("REQUEST_NOT_PENDING")

// CommitPendingDecision atomically consumes a pending request, records its
// decision and installs any persistent rules. It does not grant authority:
// callers must authenticate and validate the decision before invoking it.
// A failed transaction leaves all three unchanged; a replay cannot overwrite
// a previous decision. Session rules are in-memory and are not passed here.
func (s *Store) CommitPendingDecision(ctx context.Context, d Decision, persistentRules []rules.Rule) error {
	status := "APPROVED"
	switch d.Decision {
	case "DENY":
		status = "DENIED"
	case "ALLOW_ONCE", "ALLOW_SESSION", "ALLOW_ALWAYS":
	default:
		return fmt.Errorf("unsupported decision %q", d.Decision)
	}
	if d.Decision != "ALLOW_ALWAYS" && len(persistentRules) != 0 {
		return errors.New("persistent rules require ALLOW_ALWAYS")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE requests SET status = ? WHERE request_id = ? AND status = 'PENDING_APPROVAL'", status, d.RequestID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrRequestNotPending
	}
	if err := insertDecision(ctx, tx, d); err != nil {
		return err
	}
	for _, rule := range persistentRules {
		if err := insertAlwaysRule(ctx, tx, rule, d.DecidedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}
