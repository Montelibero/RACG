package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Request struct {
	ID           string
	SessionID    string
	ClientID     string
	Status       string
	OpJSON       string
	RiskFlagsJSON string
	CreatedAt    time.Time
}

type Decision struct {
	RequestID      string
	Decision       string
	DecisionSource string
	DecidedAt      time.Time
	RuleID         string
}

type Execution struct {
	RequestID        string
	StartedAt        time.Time
	FinishedAt       time.Time
	DurationMs       int64
	ExitCode         int
	Status           string
	Stdout           string
	Stderr           string
	StdoutTruncated  bool
	StderrTruncated  bool
	StdoutSHA256     string
	StderrSHA256     string
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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

