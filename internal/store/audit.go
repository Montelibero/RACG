package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type Request struct {
	ID            string
	SessionID     string
	ClientID      string
	Status        string
	OpJSON        string
	RiskFlagsJSON string
	CreatedAt     time.Time
}

type Decision struct {
	RequestID      string
	Decision       string
	DecisionSource string
	DecidedAt      time.Time
	RuleID         string
}

type Execution struct {
	RequestID       string
	StartedAt       time.Time
	FinishedAt      time.Time
	DurationMs      int64
	ExitCode        int
	Status          string
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	StdoutSHA256    string
	StderrSHA256    string
}

type SessionHistoryItem struct {
	RequestID       string
	ClientID        string
	Status          string
	OpJSON          string
	RiskFlagsJSON   string
	CreatedAt       time.Time
	Decision        *string
	DecisionSource  *string
	DecidedAt       *time.Time
	ExecutionStatus *string
	ExitCode        *int
	DurationMs      *int64
}

func (s *Store) InsertRequest(ctx context.Context, r Request) error {
	if r.ID == "" {
		return fmt.Errorf("request ID required")
	}
	if r.SessionID == "" {
		return fmt.Errorf("session ID required")
	}
	if r.ClientID == "" {
		return fmt.Errorf("client ID required")
	}
	if r.Status == "" {
		return fmt.Errorf("status required")
	}
	if r.OpJSON == "" {
		return fmt.Errorf("op JSON required")
	}
	if r.RiskFlagsJSON == "" {
		r.RiskFlagsJSON = "[]"
	}
	if r.CreatedAt.IsZero() {
		return fmt.Errorf("created_at required")
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO requests(request_id, session_id, client_id, status, op_json, risk_flags_json, created_at)
		 VALUES(?,         ?,          ?,         ?,      ?,      ?,              ?)`,
		r.ID,
		r.SessionID,
		r.ClientID,
		r.Status,
		r.OpJSON,
		r.RiskFlagsJSON,
		r.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) GetRequest(ctx context.Context, requestID string) (Request, error) {
	var r Request
	var created string

	row := s.db.QueryRowContext(ctx,
		`SELECT request_id, session_id, client_id, status, op_json, risk_flags_json, created_at
		   FROM requests
		  WHERE request_id = ?`,
		requestID,
	)
	if err := row.Scan(&r.ID, &r.SessionID, &r.ClientID, &r.Status, &r.OpJSON, &r.RiskFlagsJSON, &created); err != nil {
		return Request{}, err
	}
	tm, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return Request{}, err
	}
	r.CreatedAt = tm
	return r, nil
}

func (s *Store) ListRequestsByStatus(ctx context.Context, statuses []string, limit int) ([]Request, error) {
	if len(statuses) == 0 {
		return nil, fmt.Errorf("statuses required")
	}
	if limit <= 0 {
		limit = 1000
	}

	placeholders := make([]string, 0, len(statuses))
	args := make([]any, 0, len(statuses)+1)
	for _, st := range statuses {
		placeholders = append(placeholders, "?")
		args = append(args, st)
	}
	args = append(args, limit)

	q := fmt.Sprintf(
		`SELECT request_id, session_id, client_id, status, op_json, risk_flags_json, created_at
		   FROM requests
		  WHERE status IN (%s)
		  ORDER BY created_at ASC
		  LIMIT ?`,
		strings.Join(placeholders, ","),
	)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Request
	for rows.Next() {
		var r Request
		var created string
		if err := rows.Scan(&r.ID, &r.SessionID, &r.ClientID, &r.Status, &r.OpJSON, &r.RiskFlagsJSON, &created); err != nil {
			return nil, err
		}
		tm, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		r.CreatedAt = tm
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UpdateRequestStatus(ctx context.Context, requestID string, status string) error {
	if requestID == "" {
		return fmt.Errorf("request ID required")
	}
	if status == "" {
		return fmt.Errorf("status required")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE requests SET status = ? WHERE request_id = ?`, status, requestID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) InsertDecision(ctx context.Context, d Decision) error {
	if d.RequestID == "" {
		return fmt.Errorf("request ID required")
	}
	if d.Decision == "" {
		return fmt.Errorf("decision required")
	}
	if d.DecisionSource == "" {
		return fmt.Errorf("decision_source required")
	}
	if d.DecidedAt.IsZero() {
		return fmt.Errorf("decided_at required")
	}

	var ruleID sql.NullString
	if d.RuleID != "" {
		ruleID = sql.NullString{String: d.RuleID, Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO decisions(request_id, decision, decision_source, decided_at, rule_id)
		 VALUES(?,          ?,        ?,              ?,         ?)`,
		d.RequestID,
		d.Decision,
		d.DecisionSource,
		d.DecidedAt.UTC().Format(time.RFC3339Nano),
		ruleID,
	)
	return err
}

func (s *Store) GetDecision(ctx context.Context, requestID string) (Decision, error) {
	var d Decision
	var decided string
	var ruleID sql.NullString

	row := s.db.QueryRowContext(ctx,
		`SELECT request_id, decision, decision_source, decided_at, rule_id
		   FROM decisions
		  WHERE request_id = ?`,
		requestID,
	)
	if err := row.Scan(&d.RequestID, &d.Decision, &d.DecisionSource, &decided, &ruleID); err != nil {
		return Decision{}, err
	}
	tm, err := time.Parse(time.RFC3339Nano, decided)
	if err != nil {
		return Decision{}, err
	}
	d.DecidedAt = tm
	if ruleID.Valid {
		d.RuleID = ruleID.String
	}
	return d, nil
}

func (s *Store) InsertExecution(ctx context.Context, e Execution) error {
	if e.RequestID == "" {
		return fmt.Errorf("request ID required")
	}
	if e.StartedAt.IsZero() || e.FinishedAt.IsZero() {
		return fmt.Errorf("started_at and finished_at required")
	}
	if e.Status == "" {
		return fmt.Errorf("status required")
	}
	if e.StdoutSHA256 == "" || e.StderrSHA256 == "" {
		return fmt.Errorf("sha256 required")
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO executions(
		   request_id, started_at, finished_at, duration_ms, exit_code, status,
		   stdout, stderr, stdout_truncated, stderr_truncated, stdout_sha256, stderr_sha256
		 ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.RequestID,
		e.StartedAt.UTC().Format(time.RFC3339Nano),
		e.FinishedAt.UTC().Format(time.RFC3339Nano),
		e.DurationMs,
		e.ExitCode,
		e.Status,
		e.Stdout,
		e.Stderr,
		boolToInt(e.StdoutTruncated),
		boolToInt(e.StderrTruncated),
		e.StdoutSHA256,
		e.StderrSHA256,
	)
	return err
}

func (s *Store) GetExecution(ctx context.Context, requestID string) (Execution, error) {
	var e Execution
	var started string
	var finished string
	var stdoutTrunc int
	var stderrTrunc int

	row := s.db.QueryRowContext(ctx,
		`SELECT request_id, started_at, finished_at, duration_ms, exit_code, status,
		        stdout, stderr, stdout_truncated, stderr_truncated, stdout_sha256, stderr_sha256
		   FROM executions
		  WHERE request_id = ?`,
		requestID,
	)
	if err := row.Scan(
		&e.RequestID,
		&started,
		&finished,
		&e.DurationMs,
		&e.ExitCode,
		&e.Status,
		&e.Stdout,
		&e.Stderr,
		&stdoutTrunc,
		&stderrTrunc,
		&e.StdoutSHA256,
		&e.StderrSHA256,
	); err != nil {
		return Execution{}, err
	}
	st, err := time.Parse(time.RFC3339Nano, started)
	if err != nil {
		return Execution{}, err
	}
	fi, err := time.Parse(time.RFC3339Nano, finished)
	if err != nil {
		return Execution{}, err
	}
	e.StartedAt = st
	e.FinishedAt = fi
	e.StdoutTruncated = stdoutTrunc != 0
	e.StderrTruncated = stderrTrunc != 0
	return e, nil
}

func (s *Store) ListSessionHistoryItems(ctx context.Context, sessionID string, limit int) ([]SessionHistoryItem, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("session ID required")
	}
	if limit <= 0 {
		limit = 200
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT
		   r.request_id,
		   r.client_id,
		   r.status,
		   r.op_json,
		   r.risk_flags_json,
		   r.created_at,
		   d.decision,
		   d.decision_source,
		   d.decided_at,
		   e.status,
		   e.exit_code,
		   e.duration_ms
		 FROM requests r
		 LEFT JOIN decisions d ON d.request_id = r.request_id
		 LEFT JOIN executions e ON e.request_id = r.request_id
		 WHERE r.session_id = ?
		 ORDER BY r.created_at ASC
		 LIMIT ?`,
		sessionID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SessionHistoryItem
	for rows.Next() {
		var item SessionHistoryItem
		var created string
		var decision sql.NullString
		var decisionSource sql.NullString
		var decidedAt sql.NullString
		var execStatus sql.NullString
		var exitCode sql.NullInt64
		var durationMs sql.NullInt64

		if err := rows.Scan(
			&item.RequestID,
			&item.ClientID,
			&item.Status,
			&item.OpJSON,
			&item.RiskFlagsJSON,
			&created,
			&decision,
			&decisionSource,
			&decidedAt,
			&execStatus,
			&exitCode,
			&durationMs,
		); err != nil {
			return nil, err
		}

		createdAt, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		item.CreatedAt = createdAt

		if decision.Valid {
			v := decision.String
			item.Decision = &v
		}
		if decisionSource.Valid {
			v := decisionSource.String
			item.DecisionSource = &v
		}
		if decidedAt.Valid {
			tm, err := time.Parse(time.RFC3339Nano, decidedAt.String)
			if err != nil {
				return nil, err
			}
			item.DecidedAt = &tm
		}
		if execStatus.Valid {
			v := execStatus.String
			item.ExecutionStatus = &v
		}
		if exitCode.Valid {
			v := int(exitCode.Int64)
			item.ExitCode = &v
		}
		if durationMs.Valid {
			v := durationMs.Int64
			item.DurationMs = &v
		}

		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
