package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

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

func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// For now keep conservative; can be made configurable later.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	return &Store{db: db}, nil
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

func (s *Store) EndSession(ctx context.Context, id string, endedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET ended_at = ? WHERE session_id = ?`, endedAt.UTC().Format(time.RFC3339Nano), id)
	return err
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
