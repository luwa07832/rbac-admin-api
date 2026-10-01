package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound is returned when a referenced record does not exist.
var ErrNotFound = errors.New("record not found")

// ErrConflict is returned when a write violates a uniqueness or reference rule.
var ErrConflict = errors.New("record conflicts with stored data")

// ErrAlreadyOpen is returned when a create targets a relation whose identity
// already has an open validity interval; the write is idempotent at the API.
var ErrAlreadyOpen = errors.New("relation already in force")

// Entity kinds accepted by the generic record endpoints.
const (
	KindSubject    = "subject"
	KindResource   = "resource"
	KindOperation  = "operation"
	KindPermission = "permission"
	KindRole       = "role"
)

var entityTables = map[string]string{
	KindSubject:    "subjects",
	KindResource:   "resources",
	KindOperation:  "operations",
	KindPermission: "permissions",
	KindRole:       "roles",
}

// ValidEntityKind reports whether kind names one of the five record entities.
func ValidEntityKind(kind string) bool {
	_, ok := entityTables[kind]
	return ok
}

// Entity is the shared representation of a subject, resource, operation,
// permission point or role record.
type Entity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PutEntity creates or replaces a record.
func (s *Store) PutEntity(kind, id, name string) error {
	table, ok := entityTables[kind]
	if !ok {
		return fmt.Errorf("unknown entity kind %q", kind)
	}
	_, err := s.db.Exec(
		`INSERT INTO `+table+` (id, name) VALUES (?, ?)
		 ON CONFLICT(id) DO UPDATE SET name = excluded.name`,
		id, name,
	)
	return mapErr(err)
}

// GetEntity loads one record.
func (s *Store) GetEntity(kind, id string) (Entity, error) {
	table, ok := entityTables[kind]
	if !ok {
		return Entity{}, fmt.Errorf("unknown entity kind %q", kind)
	}
	var entity Entity
	err := s.db.QueryRow(`SELECT id, name FROM `+table+` WHERE id = ?`, id).
		Scan(&entity.ID, &entity.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return Entity{}, ErrNotFound
	}
	if err != nil {
		return Entity{}, mapErr(err)
	}
	return entity, nil
}

// ListEntities returns every record of one kind ordered by id.
func (s *Store) ListEntities(kind string) ([]Entity, error) {
	table, ok := entityTables[kind]
	if !ok {
		return nil, fmt.Errorf("unknown entity kind %q", kind)
	}
	rows, err := s.db.Query(`SELECT id, name FROM ` + table + ` ORDER BY id ASC`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	entities := make([]Entity, 0)
	for rows.Next() {
		var entity Entity
		if err := rows.Scan(&entity.ID, &entity.Name); err != nil {
			return nil, mapErr(err)
		}
		entities = append(entities, entity)
	}
	return entities, mapErr(rows.Err())
}

// DeleteEntity removes one record. Referenced records fail with ErrConflict.
func (s *Store) DeleteEntity(kind, id string) error {
	table, ok := entityTables[kind]
	if !ok {
		return fmt.Errorf("unknown entity kind %q", kind)
	}
	result, err := s.db.Exec(`DELETE FROM `+table+` WHERE id = ?`, id)
	if err != nil {
		return mapErr(err)
	}
	return requireAffected(result)
}

// Exists reports whether a record of the given kind is stored.
func (s *Store) Exists(kind, id string) (bool, error) {
	table, ok := entityTables[kind]
	if !ok {
		return false, fmt.Errorf("unknown entity kind %q", kind)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE id = ?`, id).
		Scan(&count); err != nil {
		return false, mapErr(err)
	}
	return count > 0, nil
}

// AddLink creates a row in a fixed-allowlist link table. Every referenced
// table/column comes from the table below, never from request input.
func (s *Store) AddLink(link string, args ...any) error {
	stmt, ok := linkInsert[link]
	if !ok {
		return fmt.Errorf("unknown link %q", link)
	}
	_, err := s.db.Exec(stmt, args...)
	return mapErr(err)
}

// RemoveLink deletes a row from a fixed-allowlist link table.
func (s *Store) RemoveLink(link string, args ...any) error {
	stmt, ok := linkDelete[link]
	if !ok {
		return fmt.Errorf("unknown link %q", link)
	}
	result, err := s.db.Exec(stmt, args...)
	if err != nil {
		return mapErr(err)
	}
	return requireAffected(result)
}

// Close reasons recorded on a version interval. They drive the distinction
// between UPDATE and REVOKE events when history is rebuilt.
const (
	CloseRevoke = "revoke"
	CloseUpdate = "update"
)

// intervalTable describes one of the three versioned relation tables.
type intervalTable struct {
	name   string
	insert string
	open   string
}

var intervalTables = map[string]intervalTable{
	"subject_role_intervals": {
		name: "subject_role_intervals",
		insert: `INSERT INTO subject_role_intervals
			(subject_id, role_id, scope_kind, scope_value, valid_from, valid_to, close_reason, seq)
			VALUES (?, ?, ?, ?, ?, NULL, '', ?)`,
		open: `SELECT id, valid_from, seq FROM subject_role_intervals
			WHERE subject_id = ? AND role_id = ? AND scope_kind = ? AND scope_value = ? AND valid_to IS NULL`,
	},
	"direct_grant_intervals": {
		name: "direct_grant_intervals",
		insert: `INSERT INTO direct_grant_intervals
			(subject_id, permission_id, scope_kind, scope_value, valid_from, valid_to, close_reason, seq)
			VALUES (?, ?, ?, ?, ?, NULL, '', ?)`,
		open: `SELECT id, valid_from, seq FROM direct_grant_intervals
			WHERE subject_id = ? AND permission_id = ? AND scope_kind = ? AND scope_value = ? AND valid_to IS NULL`,
	},
	"role_permission_intervals": {
		name: "role_permission_intervals",
		insert: `INSERT INTO role_permission_intervals
			(role_id, permission_id, valid_from, valid_to, close_reason, seq)
			VALUES (?, ?, ?, NULL, '', ?)`,
		open: `SELECT id, valid_from, seq FROM role_permission_intervals
			WHERE role_id = ? AND permission_id = ? AND valid_to IS NULL`,
	},
}

// openIntervalID returns the open interval id for the identity columns, or
// ErrNotFound when none is open.
func (s *Store) openIntervalID(table string, identity ...any) (int64, bool, error) {
	definition, ok := intervalTables[table]
	if !ok {
		return 0, false, fmt.Errorf("unknown interval table %q", table)
	}
	var id int64
	var from, seq int64
	err := s.db.QueryRow(definition.open, identity...).Scan(&id, &from, &seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, mapErr(err)
	}
	return id, true, nil
}

// openVersion reports whether an interval with the same identity is still open.
func (s *Store) openVersion(table string, identity ...any) (bool, error) {
	_, exists, err := s.openIntervalID(table, identity...)
	return exists, err
}

// closeOpen ends the open interval for identity at when with reason. It returns
// ErrNotFound when no open interval exists.
func (s *Store) closeOpen(table string, when int64, reason string, identity ...any) error {
	id, open, err := s.openIntervalID(table, identity...)
	if err != nil {
		return err
	}
	if !open {
		return ErrNotFound
	}
	result, err := s.db.Exec(
		`UPDATE `+intervalTables[table].name+` SET valid_to = ?, close_reason = ? WHERE id = ?`,
		when, reason, id)
	if err != nil {
		return mapErr(err)
	}
	return requireAffected(result)
}

func (s *Store) insertVersion(table string, when int64, cols ...any) error {
	definition, ok := intervalTables[table]
	if !ok {
		return fmt.Errorf("unknown interval table %q", table)
	}
	seq := s.seq + 1
	args := make([]any, 0, len(cols)+2)
	for _, value := range cols {
		args = append(args, value)
	}
	args = append(args, when, seq)
	_, err := s.db.Exec(definition.insert, args...)
	if err != nil {
		return mapErr(err)
	}
	s.seq = seq
	return nil
}

func requireAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return mapErr(err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if strings.Contains(message, "FOREIGN KEY constraint failed") ||
		strings.Contains(message, "UNIQUE constraint failed") ||
		strings.Contains(message, "CHECK constraint failed") {
		return fmt.Errorf("%w: %s", ErrConflict, message)
	}
	return err
}
