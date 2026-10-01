package store

import (
	"database/sql"
	"strings"
)

func nullString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

// grantVersion rejects an already-open interval for the same identity and
// inserts a new GRANT interval.
func (s *Store) grantVersion(table, matchClause string, matchArgs []interface{}, columns string, values []interface{}) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := ensureNoOpenInTx(tx, table, matchClause, matchArgs); err != nil {
		return err
	}
	if err := insertVersionInTx(tx, table, columns, values...); err != nil {
		return err
	}
	return tx.Commit()
}

// revokeVersionAt closes the open interval of the identity and appends a
// zero-length REVOKE row that keeps the change visible in history. The
// identity columns are expected to be the first columns of the table and the
// version columns to follow the shared (event, occurred_at, effective_from,
// effective_to) suffix.
func (s *Store) revokeVersionAt(table, matchClause string, matchArgs []interface{}, columns string, identityValues []interface{}, occurredAt, effectiveFrom string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var storedOccurred, storedFrom string
	query := "SELECT occurred_at, effective_from FROM " + table + " WHERE " + matchClause +
		" AND effective_to IS NULL ORDER BY id DESC LIMIT 1"
	if err := tx.QueryRow(query, matchArgs...).Scan(&storedOccurred, &storedFrom); err != nil {
		if err == sql.ErrNoRows {
			return apiError(TypeNotFound, "", "no effective record exists to revoke")
		}
		return err
	}
	if occurredAt == "" {
		occurredAt = storedOccurred
	}
	if effectiveFrom == "" {
		effectiveFrom = storedFrom
	}

	if err := closeOpenInTx(tx, table, matchClause, matchArgs, effectiveFrom); err != nil {
		return err
	}
	values := append(append([]interface{}{}, identityValues...), EventRevoke, occurredAt, effectiveFrom, effectiveFrom)
	if err := insertVersionInTx(tx, table, columns, values...); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureNoOpenInTx(tx *sql.Tx, table, matchClause string, matchArgs []interface{}) error {
	var count int
	if err := tx.QueryRow(
		"SELECT COUNT(1) FROM "+table+" WHERE "+matchClause+" AND effective_to IS NULL",
		matchArgs...).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return apiError(TypeConflict, "", "an effective record already exists for this identity")
	}
	return nil
}

func closeOpenInTx(tx *sql.Tx, table, matchClause string, matchArgs []interface{}, effectiveTo string) error {
	result, err := tx.Exec(
		"UPDATE "+table+" SET effective_to = ? WHERE "+matchClause+" AND effective_to IS NULL",
		append([]interface{}{effectiveTo}, matchArgs...)...)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return apiError(TypeNotFound, "", "no effective record exists to change")
	}
	return nil
}

// insertVersionInTx appends one change_log row (the global ordering key) and
// one version row carrying that key.
func insertVersionInTx(tx *sql.Tx, table, columns string, values ...interface{}) error {
	result, err := tx.Exec("INSERT INTO change_log (id) VALUES (NULL)")
	if err != nil {
		return err
	}
	seq, err := result.LastInsertId()
	if err != nil {
		return err
	}
	columns = "seq, " + columns
	values = append([]interface{}{seq}, values...)
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")
	_, err = tx.Exec("INSERT INTO "+table+" ("+columns+") VALUES ("+placeholders+")", values...)
	return err
}
