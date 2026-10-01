package store

import "database/sql"

// Event tags stored on every interval version and returned by history.
const (
	EventGrant  = "GRANT"
	EventUpdate = "UPDATE"
	EventRevoke = "REVOKE"
)

// BindingVersion is one interval of a subject/role binding.
type BindingVersion struct {
	ID            int64
	Seq           int64
	SubjectID     string
	RoleID        string
	Event         string
	OccurredAt    string
	EffectiveFrom string
	EffectiveTo   string
}

// RolePermissionVersion is one interval of a role/permission grant.
type RolePermissionVersion struct {
	ID            int64
	Seq           int64
	RoleID        string
	PermissionID  string
	Event         string
	OccurredAt    string
	EffectiveFrom string
	EffectiveTo   string
}

// ScopeVersion is one interval of a scoped authorization. Exactly one of
// RoleID and PermissionID is set.
type ScopeVersion struct {
	ID            int64
	Seq           int64
	SubjectID     string
	RoleID        string
	PermissionID  string
	ScopeText     string
	Event         string
	OccurredAt    string
	EffectiveFrom string
	EffectiveTo   string
}

func scanEffectiveTo(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

// GrantBinding opens a new interval for the subject/role identity.
func (s *Store) GrantBinding(subjectID, roleID, occurredAt, effectiveFrom string) error {
	return s.grantVersion("binding_versions",
		"subject_id = ? AND role_id = ?",
		[]interface{}{subjectID, roleID},
		"subject_id, role_id, event, occurred_at, effective_from, effective_to",
		[]interface{}{subjectID, roleID, EventGrant, occurredAt, effectiveFrom, nil})
}

// UpdateBinding closes the open interval on the old role and opens one on the
// new role. The new version carries the UPDATE event.
func (s *Store) UpdateBinding(subjectID, oldRoleID, newRoleID, occurredAt, effectiveFrom string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := closeOpenInTx(tx, "binding_versions",
		"subject_id = ? AND role_id = ?",
		[]interface{}{subjectID, oldRoleID}, effectiveFrom); err != nil {
		return err
	}
	if err := ensureNoOpenInTx(tx, "binding_versions",
		"subject_id = ? AND role_id = ?",
		[]interface{}{subjectID, newRoleID}); err != nil {
		return err
	}
	if err := insertVersionInTx(tx, "binding_versions",
		"subject_id, role_id, event, occurred_at, effective_from, effective_to",
		subjectID, newRoleID, EventUpdate, occurredAt, effectiveFrom, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeBinding closes the open interval and records a zero-length REVOKE row.
func (s *Store) RevokeBinding(subjectID, roleID, occurredAt, effectiveFrom string) error {
	return s.revokeVersionAt("binding_versions",
		"subject_id = ? AND role_id = ?",
		[]interface{}{subjectID, roleID},
		"subject_id, role_id, event, occurred_at, effective_from, effective_to",
		[]interface{}{subjectID, roleID}, occurredAt, effectiveFrom)
}

// ListBindingVersions returns every interval version for the subject.
func (s *Store) ListBindingVersions(subjectID string) ([]BindingVersion, error) {
	rows, err := s.db.Query(`
		SELECT id, seq, subject_id, role_id, event, occurred_at, effective_from, effective_to
		FROM binding_versions WHERE subject_id = ?`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []BindingVersion
	for rows.Next() {
		var version BindingVersion
		var effectiveTo sql.NullString
		if err := rows.Scan(&version.ID, &version.Seq, &version.SubjectID, &version.RoleID,
			&version.Event, &version.OccurredAt, &version.EffectiveFrom, &effectiveTo); err != nil {
			return nil, err
		}
		version.EffectiveTo = scanEffectiveTo(effectiveTo)
		result = append(result, version)
	}
	return result, rows.Err()
}

// GrantRolePermission opens a new interval for the role/permission identity.
func (s *Store) GrantRolePermission(roleID, permissionID, occurredAt, effectiveFrom string) error {
	return s.grantVersion("role_permission_versions",
		"role_id = ? AND permission_id = ?",
		[]interface{}{roleID, permissionID},
		"role_id, permission_id, event, occurred_at, effective_from, effective_to",
		[]interface{}{roleID, permissionID, EventGrant, occurredAt, effectiveFrom, nil})
}

// UpdateRolePermission moves the open interval from one identity to another.
func (s *Store) UpdateRolePermission(oldRoleID, oldPermissionID, newRoleID, newPermissionID, occurredAt, effectiveFrom string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := closeOpenInTx(tx, "role_permission_versions",
		"role_id = ? AND permission_id = ?",
		[]interface{}{oldRoleID, oldPermissionID}, effectiveFrom); err != nil {
		return err
	}
	if err := ensureNoOpenInTx(tx, "role_permission_versions",
		"role_id = ? AND permission_id = ?",
		[]interface{}{newRoleID, newPermissionID}); err != nil {
		return err
	}
	if err := insertVersionInTx(tx, "role_permission_versions",
		"role_id, permission_id, event, occurred_at, effective_from, effective_to",
		newRoleID, newPermissionID, EventUpdate, occurredAt, effectiveFrom, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeRolePermission closes the open role/permission interval.
func (s *Store) RevokeRolePermission(roleID, permissionID, occurredAt, effectiveFrom string) error {
	return s.revokeVersionAt("role_permission_versions",
		"role_id = ? AND permission_id = ?",
		[]interface{}{roleID, permissionID},
		"role_id, permission_id, event, occurred_at, effective_from, effective_to",
		[]interface{}{roleID, permissionID}, occurredAt, effectiveFrom)
}

// ListRolePermissionVersions returns every role/permission interval version.
func (s *Store) ListRolePermissionVersions() ([]RolePermissionVersion, error) {
	rows, err := s.db.Query(`
		SELECT id, seq, role_id, permission_id, event, occurred_at, effective_from, effective_to
		FROM role_permission_versions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []RolePermissionVersion
	for rows.Next() {
		var version RolePermissionVersion
		var effectiveTo sql.NullString
		if err := rows.Scan(&version.ID, &version.Seq, &version.RoleID, &version.PermissionID,
			&version.Event, &version.OccurredAt, &version.EffectiveFrom, &effectiveTo); err != nil {
			return nil, err
		}
		version.EffectiveTo = scanEffectiveTo(effectiveTo)
		result = append(result, version)
	}
	return result, rows.Err()
}

func scopeMatch(subjectID, roleID, permissionID, scopeText string) (string, []interface{}) {
	return "subject_id = ? AND role_id IS ? AND permission_id IS ? AND scope_text = ?",
		[]interface{}{subjectID, nullString(roleID), nullString(permissionID), scopeText}
}

// GrantScope opens a new interval for the scoped authorization identity.
func (s *Store) GrantScope(subjectID, roleID, permissionID, scopeText, occurredAt, effectiveFrom string) error {
	clause, args := scopeMatch(subjectID, roleID, permissionID, scopeText)
	return s.grantVersion("scope_versions", clause, args,
		"subject_id, role_id, permission_id, scope_text, event, occurred_at, effective_from, effective_to",
		[]interface{}{subjectID, nullString(roleID), nullString(permissionID), scopeText,
			EventGrant, occurredAt, effectiveFrom, nil})
}

// UpdateScope closes the open interval of the old identity and opens one for
// the new identity carrying the UPDATE event.
func (s *Store) UpdateScope(subjectID, oldRoleID, oldPermissionID, oldScope,
	newRoleID, newPermissionID, newScope, occurredAt, effectiveFrom string) error {

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	oldClause, oldArgs := scopeMatch(subjectID, oldRoleID, oldPermissionID, oldScope)
	if err := closeOpenInTx(tx, "scope_versions", oldClause, oldArgs, effectiveFrom); err != nil {
		return err
	}
	newClause, newArgs := scopeMatch(subjectID, newRoleID, newPermissionID, newScope)
	if err := ensureNoOpenInTx(tx, "scope_versions", newClause, newArgs); err != nil {
		return err
	}
	if err := insertVersionInTx(tx, "scope_versions",
		"subject_id, role_id, permission_id, scope_text, event, occurred_at, effective_from, effective_to",
		subjectID, nullString(newRoleID), nullString(newPermissionID), newScope,
		EventUpdate, occurredAt, effectiveFrom, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeScope closes the open interval and records a zero-length REVOKE row.
func (s *Store) RevokeScope(subjectID, roleID, permissionID, scopeText, occurredAt, effectiveFrom string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	clause, args := scopeMatch(subjectID, roleID, permissionID, scopeText)
	if err := closeOpenInTx(tx, "scope_versions", clause, args, effectiveFrom); err != nil {
		return err
	}
	if err := insertVersionInTx(tx, "scope_versions",
		"subject_id, role_id, permission_id, scope_text, event, occurred_at, effective_from, effective_to",
		subjectID, nullString(roleID), nullString(permissionID), scopeText,
		EventRevoke, occurredAt, effectiveFrom, effectiveFrom); err != nil {
		return err
	}
	return tx.Commit()
}

// ListScopeVersions returns every scoped authorization interval for subject.
func (s *Store) ListScopeVersions(subjectID string) ([]ScopeVersion, error) {
	rows, err := s.db.Query(`
		SELECT id, seq, subject_id, role_id, permission_id, scope_text, event,
		       occurred_at, effective_from, effective_to
		FROM scope_versions WHERE subject_id = ?`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ScopeVersion
	for rows.Next() {
		var version ScopeVersion
		var roleID, permissionID, effectiveTo sql.NullString
		if err := rows.Scan(&version.ID, &version.Seq, &version.SubjectID, &roleID, &permissionID,
			&version.ScopeText, &version.Event, &version.OccurredAt,
			&version.EffectiveFrom, &effectiveTo); err != nil {
			return nil, err
		}
		version.RoleID = roleID.String
		version.PermissionID = permissionID.String
		version.EffectiveTo = scanEffectiveTo(effectiveTo)
		result = append(result, version)
	}
	return result, rows.Err()
}
