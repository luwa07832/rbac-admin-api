// Package store owns the SQLite file and every write the service performs.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db        *sql.DB
	seq       int64
	lastWrite int64
	now       func() time.Time
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	dsn := path
	if strings.Contains(path, "?") {
		dsn += "&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	} else {
		dsn += "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// A single connection keeps the foreign_keys pragma and writes deterministic.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	s := &Store{db: db, now: time.Now}
	if err := s.loadSequence(); err != nil {
		db.Close()
		return nil, fmt.Errorf("load sequence: %w", err)
	}
	return s, nil
}

// SetClock overrides the wall clock writes use to stamp valid intervals. It is
// meant for deterministic storage tests; production code keeps the default.
func (s *Store) SetClock(clock func() time.Time) {
	if clock != nil {
		s.now = clock
	}
}

func (s *Store) nowNanos() int64 { return s.now().UTC().UnixNano() }

// writeInstant returns the effective timestamp a new write uses. Real wall
// time is preferred, but when the clock does not advance the instant moves
// forward by one nanosecond so every change forms a distinct, ordered window.
func (s *Store) writeInstant() int64 {
	candidate := s.now().UTC().UnixNano()
	if candidate <= s.lastWrite {
		candidate = s.lastWrite + 1
	}
	s.lastWrite = candidate
	return candidate
}

func (s *Store) loadSequence() error {
	var maxSeq sql.NullInt64
	var maxWhen sql.NullInt64
	for _, table := range []string{"subject_role_intervals", "direct_grant_intervals", "role_permission_intervals"} {
		var seq sql.NullInt64
		if err := s.db.QueryRow(`SELECT MAX(seq) FROM ` + table).Scan(&seq); err != nil {
			return err
		}
		if seq.Valid && seq.Int64 > maxSeq.Int64 {
			maxSeq = seq
		}
		var when sql.NullInt64
		if err := s.db.QueryRow(`SELECT MAX(valid_from) FROM ` + table).Scan(&when); err != nil {
			return err
		}
		if when.Valid && when.Int64 > maxWhen.Int64 {
			maxWhen = when
		}
	}
	s.seq = maxSeq.Int64
	s.lastWrite = maxWhen.Int64
	return nil
}

// Ping reports whether the storage layer is usable.
func (s *Store) Ping() error { return s.db.Ping() }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS service_metadata (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subjects (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS resources (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS operations (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS permissions (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS roles (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS permission_operations (
	permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
	operation_id  TEXT NOT NULL REFERENCES operations(id)  ON DELETE RESTRICT,
	PRIMARY KEY (permission_id, operation_id)
);
CREATE TABLE IF NOT EXISTS role_inheritance (
	role_id     TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
	parent_id   TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
	PRIMARY KEY (role_id, parent_id),
	CHECK (role_id <> parent_id)
);
CREATE TABLE IF NOT EXISTS subject_role_intervals (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	subject_id   TEXT NOT NULL REFERENCES subjects(id) ON DELETE RESTRICT,
	role_id      TEXT NOT NULL REFERENCES roles(id)    ON DELETE RESTRICT,
	scope_kind   TEXT NOT NULL CHECK (scope_kind IN ('exact','prefix','all')),
	scope_value  TEXT NOT NULL DEFAULT '',
	valid_from   INTEGER NOT NULL,
	valid_to     INTEGER,
	close_reason TEXT NOT NULL DEFAULT '',
	seq          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sri_subject
	ON subject_role_intervals (subject_id, valid_from);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sri_open ON subject_role_intervals
	(subject_id, role_id, scope_kind, scope_value) WHERE valid_to IS NULL;
CREATE TABLE IF NOT EXISTS direct_grant_intervals (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	subject_id   TEXT NOT NULL REFERENCES subjects(id)    ON DELETE RESTRICT,
	permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
	scope_kind   TEXT NOT NULL CHECK (scope_kind IN ('exact','prefix','all')),
	scope_value  TEXT NOT NULL DEFAULT '',
	valid_from   INTEGER NOT NULL,
	valid_to     INTEGER,
	close_reason TEXT NOT NULL DEFAULT '',
	seq          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dgi_subject
	ON direct_grant_intervals (subject_id, valid_from);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dgi_open ON direct_grant_intervals
	(subject_id, permission_id, scope_kind, scope_value) WHERE valid_to IS NULL;
CREATE TABLE IF NOT EXISTS role_permission_intervals (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	role_id       TEXT NOT NULL REFERENCES roles(id)       ON DELETE RESTRICT,
	permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
	valid_from    INTEGER NOT NULL,
	valid_to      INTEGER,
	close_reason  TEXT NOT NULL DEFAULT '',
	seq           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rpi_role
	ON role_permission_intervals (role_id, valid_from);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rpi_open ON role_permission_intervals
	(role_id, permission_id) WHERE valid_to IS NULL;
`
