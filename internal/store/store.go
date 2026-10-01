// Package store owns the SQLite file and every write the service performs.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Error type tags shared with the public error contract.
const (
	TypeNotFound       = "NOT_FOUND"
	TypeInvalidRequest = "INVALID_REQUEST"
	TypeInvalidTime    = "INVALID_TIME"
	TypeInvalidRange   = "INVALID_RANGE"
	TypeConflict       = "CONFLICT"
)

// Error is the structured failure raised by store operations. Callers map it
// onto the public error object; Message never carries SQL or file details.
type Error struct {
	Type    string
	Field   string
	Message string
}

func (e *Error) Error() string { return e.Type + ": " + e.Message }

func apiError(typ, field, message string) *Error {
	return &Error{Type: typ, Field: field, Message: message}
}

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db *sql.DB
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
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
	id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS resources (
	id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS operations (
	id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS roles (
	id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS role_parents (
	role_id   TEXT NOT NULL,
	parent_id TEXT NOT NULL,
	position  INTEGER NOT NULL,
	PRIMARY KEY (role_id, parent_id),
	FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
	FOREIGN KEY (parent_id) REFERENCES roles(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS permissions (
	id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS permission_operations (
	permission_id TEXT NOT NULL,
	operation_id  TEXT NOT NULL,
	position      INTEGER NOT NULL,
	PRIMARY KEY (permission_id, operation_id),
	FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
	FOREIGN KEY (operation_id) REFERENCES operations(id) ON DELETE CASCADE
);

-- Every versioned layer keeps one row per interval version. Times are stored
-- as RFC3339Nano UTC strings, so lexicographic order is chronological order;
-- effective_to IS NULL marks the currently open interval. Intervals are
-- half-open: effective_from <= t < effective_to.
CREATE TABLE IF NOT EXISTS binding_versions (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	seq              INTEGER NOT NULL,
	subject_id       TEXT NOT NULL,
	role_id          TEXT NOT NULL,
	event            TEXT NOT NULL,
	occurred_at      TEXT NOT NULL,
	effective_from   TEXT NOT NULL,
	effective_to     TEXT
);
CREATE INDEX IF NOT EXISTS idx_binding_lookup
	ON binding_versions (subject_id, role_id, effective_from);

CREATE TABLE IF NOT EXISTS role_permission_versions (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	seq              INTEGER NOT NULL,
	role_id          TEXT NOT NULL,
	permission_id    TEXT NOT NULL,
	event            TEXT NOT NULL,
	occurred_at      TEXT NOT NULL,
	effective_from   TEXT NOT NULL,
	effective_to     TEXT
);
CREATE INDEX IF NOT EXISTS idx_role_permission_lookup
	ON role_permission_versions (role_id, permission_id, effective_from);

CREATE TABLE IF NOT EXISTS scope_versions (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	seq              INTEGER NOT NULL,
	subject_id       TEXT NOT NULL,
	role_id          TEXT,
	permission_id    TEXT,
	scope_text       TEXT NOT NULL,
	event            TEXT NOT NULL,
	occurred_at      TEXT NOT NULL,
	effective_from   TEXT NOT NULL,
	effective_to     TEXT
);

-- Global change ordering: every GRANT/UPDATE/REVOKE inserts one row, so the
-- id is the stable tiebreak for changes sharing effectiveFrom/occurredAt.
CREATE TABLE IF NOT EXISTS change_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT
);
CREATE INDEX IF NOT EXISTS idx_scope_lookup
	ON scope_versions (subject_id, effective_from);
`
