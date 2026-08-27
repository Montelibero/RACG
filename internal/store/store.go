package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/rules"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Store struct {
	db *sql.DB
}

type Session struct {
	ID        string
	StartedAt time.Time
	EndedAt   *time.Time
}

type RuleRow struct {
	RuleID      string
	Source      string
	OpType      string
	Enabled     bool
	CreatedAt   time.Time
	DisabledAt  *time.Time
	CmdArgvJSON *string
	PathExact   *string
	PathPrefix  *string
	PathGlob    *string
}

func Open(dsn string) (*Store, error) {
	if err := ensureDBParentDir(dsn); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// For now keep conservative; can be made configurable later.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	return &Store{db: db}, nil
}

func ensureDBParentDir(dsn string) error {
	if dsn == "" || strings.HasPrefix(dsn, "file:") || strings.Contains(dsn, ":memory:") {
		return nil
	}
	dir := filepath.Dir(dsn)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);`); err != nil {
		return err
	}

	applied := map[int]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return err
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, name := range names {
		ver, err := migrationVersion(name)
		if err != nil {
			return err
		}
		if applied[ver] {
			continue
		}

		b, err := migrationsFS.ReadFile(filepath.Join("migrations", name))
		if err != nil {
			return err
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(ctx, string(b)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s failed: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, ver, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) InsertSession(ctx context.Context, sess Session) error {
	if sess.ID == "" {
		return fmt.Errorf("session ID required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(session_id, started_at, ended_at) VALUES(?, ?, NULL)`,
		sess.ID,
		sess.StartedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	var sess Session
	var started string
	var ended sql.NullString

	row := s.db.QueryRowContext(ctx, `SELECT session_id, started_at, ended_at FROM sessions WHERE session_id = ?`, id)
	if err := row.Scan(&sess.ID, &started, &ended); err != nil {
		return Session{}, err
	}
	st, err := time.Parse(time.RFC3339Nano, started)
	if err != nil {
		return Session{}, err
	}
	sess.StartedAt = st
	if ended.Valid {
		tm, err := time.Parse(time.RFC3339Nano, ended.String)
		if err != nil {
			return Session{}, err
		}
		sess.EndedAt = &tm
	}
	return sess, nil
}

func (s *Store) ListSessions(ctx context.Context, limit int) ([]Session, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT session_id, started_at, ended_at FROM sessions ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

func (s *Store) ListOpenSessions(ctx context.Context) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT session_id, started_at, ended_at FROM sessions WHERE ended_at IS NULL ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSessions(rows)
}

func scanSessions(rows *sql.Rows) ([]Session, error) {
	var out []Session
	for rows.Next() {
		var sess Session
		var started string
		var ended sql.NullString
		if err := rows.Scan(&sess.ID, &started, &ended); err != nil {
			return nil, err
		}
		st, err := time.Parse(time.RFC3339Nano, started)
		if err != nil {
			return nil, err
		}
		sess.StartedAt = st
		if ended.Valid {
			tm, err := time.Parse(time.RFC3339Nano, ended.String)
			if err != nil {
				return nil, err
			}
			sess.EndedAt = &tm
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) EndSession(ctx context.Context, id string, endedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET ended_at = ? WHERE session_id = ?`, endedAt.UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) InsertAlwaysRule(ctx context.Context, r rules.Rule, createdAt time.Time) error {
	if r.ID == "" {
		return fmt.Errorf("rule ID required")
	}
	if strings.TrimSpace(r.OpType) == "" {
		return fmt.Errorf("op type required")
	}

	var argvJSON sql.NullString
	var pathExact sql.NullString
	var pathPrefix sql.NullString
	var pathGlob sql.NullString

	if r.Cmd != nil && len(r.Cmd.ArgvPrefix) > 0 {
		b, err := json.Marshal(r.Cmd.ArgvPrefix)
		if err != nil {
			return err
		}
		argvJSON = sql.NullString{String: string(b), Valid: true}
	}
	if r.Path != nil {
		if r.Path.Exact != "" {
			pathExact = sql.NullString{String: r.Path.Exact, Valid: true}
		}
		if r.Path.Prefix != "" {
			pathPrefix = sql.NullString{String: r.Path.Prefix, Valid: true}
		}
		if r.Path.Glob != "" {
			pathGlob = sql.NullString{String: r.Path.Glob, Valid: true}
		}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rules(rule_id, source, op_type, cmd_argv_prefix_json, cmd_stdin_sha256, path_exact, path_prefix, path_glob, enabled, created_at, disabled_at)
		 VALUES(?,      ?,      ?,       ?,                    ?,                ?,          ?,           ?,         1,       ?,          NULL)`,
		r.ID,
		"always",
		r.OpType,
		argvJSON,
		nil,
		pathExact,
		pathPrefix,
		pathGlob,
		createdAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) LoadEnabledAlwaysRules(ctx context.Context) ([]rules.Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_id, op_type, cmd_argv_prefix_json, cmd_stdin_sha256, path_exact, path_prefix, path_glob
		   FROM rules
		  WHERE source = 'always' AND enabled = 1
		  ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []rules.Rule
	for rows.Next() {
		var id string
		var opType string
		var argvJSON sql.NullString
		var legacyStdinSHA256 sql.NullString
		var pathExact sql.NullString
		var pathPrefix sql.NullString
		var pathGlob sql.NullString
		if err := rows.Scan(&id, &opType, &argvJSON, &legacyStdinSHA256, &pathExact, &pathPrefix, &pathGlob); err != nil {
			return nil, err
		}

		r := rules.Rule{ID: id, OpType: opType}
		if argvJSON.Valid && strings.TrimSpace(argvJSON.String) != "" {
			var argv []string
			if err := json.Unmarshal([]byte(argvJSON.String), &argv); err != nil {
				return nil, err
			}
			if len(argv) > 0 {
				r.Cmd = &rules.CmdRule{ArgvPrefix: argv}
			}
		}
		if pathExact.Valid || pathPrefix.Valid || pathGlob.Valid {
			pr := rules.PathRule{}
			if pathExact.Valid {
				pr.Exact = pathExact.String
			}
			if pathPrefix.Valid {
				pr.Prefix = pathPrefix.String
			}
			if pathGlob.Valid {
				pr.Glob = pathGlob.String
			}
			r.Path = &pr
		}

		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) DisableRule(ctx context.Context, ruleID string, disabledAt time.Time) error {
	if strings.TrimSpace(ruleID) == "" {
		return fmt.Errorf("rule ID required")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE rules
		    SET enabled = 0, disabled_at = ?
		  WHERE rule_id = ? AND enabled = 1`,
		disabledAt.UTC().Format(time.RFC3339Nano),
		ruleID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("RULE_NOT_FOUND")
	}
	return nil
}

func (s *Store) EnableRule(ctx context.Context, ruleID string) error {
	if strings.TrimSpace(ruleID) == "" {
		return fmt.Errorf("rule ID required")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE rules
		    SET enabled = 1, disabled_at = NULL
		  WHERE rule_id = ? AND enabled = 0`,
		ruleID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("RULE_NOT_FOUND")
	}
	return nil
}

func (s *Store) DeleteRule(ctx context.Context, ruleID string) error {
	if strings.TrimSpace(ruleID) == "" {
		return fmt.Errorf("rule ID required")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE rule_id = ?`, ruleID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("RULE_NOT_FOUND")
	}
	return nil
}

func (s *Store) ListRules(ctx context.Context, limit int) ([]RuleRow, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_id, source, op_type, enabled, created_at, disabled_at, cmd_argv_prefix_json, path_exact, path_prefix, path_glob
		   FROM rules
		  ORDER BY created_at DESC
		  LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RuleRow
	for rows.Next() {
		var rr RuleRow
		var enabledInt int
		var created string
		var disabled sql.NullString
		var cmdJSON sql.NullString
		var pathExact sql.NullString
		var pathPrefix sql.NullString
		var pathGlob sql.NullString

		if err := rows.Scan(
			&rr.RuleID,
			&rr.Source,
			&rr.OpType,
			&enabledInt,
			&created,
			&disabled,
			&cmdJSON,
			&pathExact,
			&pathPrefix,
			&pathGlob,
		); err != nil {
			return nil, err
		}

		rr.Enabled = enabledInt != 0
		tm, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		rr.CreatedAt = tm
		if disabled.Valid {
			dt, err := time.Parse(time.RFC3339Nano, disabled.String)
			if err != nil {
				return nil, err
			}
			rr.DisabledAt = &dt
		}
		if cmdJSON.Valid {
			v := cmdJSON.String
			rr.CmdArgvJSON = &v
		}
		if pathExact.Valid {
			v := pathExact.String
			rr.PathExact = &v
		}
		if pathPrefix.Valid {
			v := pathPrefix.String
			rr.PathPrefix = &v
		}
		if pathGlob.Valid {
			v := pathGlob.String
			rr.PathGlob = &v
		}
		out = append(out, rr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func migrationVersion(filename string) (int, error) {
	// Expect: NNN_description.sql
	base := filepath.Base(filename)
	parts := strings.SplitN(base, "_", 2)
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid migration filename: %q", filename)
	}
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid migration version in %q: %w", filename, err)
	}
	return v, nil
}
