package store

import (
	"database/sql"
)

const (
	tableSubjectRoles    = "subject_role_intervals"
	tableDirectGrants    = "direct_grant_intervals"
	tableRolePermissions = "role_permission_intervals"
)

// BindScope is the authorization scope attached to a binding or direct grant.
type BindScope struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// BindSubjectRole opens a new validity interval attaching role to a subject for
// the given scope. The same identity being open is idempotent: callers receive
// ErrAlreadyOpen and no extra row is stored.
func (s *Store) BindSubjectRole(subjectID, roleID, kind, value string) error {
	open, err := s.openVersion(tableSubjectRoles, subjectID, roleID, kind, value)
	if err != nil || open {
		if open {
			return ErrAlreadyOpen
		}
		return err
	}
	return s.insertVersion(tableSubjectRoles, s.writeInstant(), subjectID, roleID, kind, value)
}

// UnbindSubjectRole closes the open interval for one scoped subject-role
// binding. Revoking a relation that is not in force fails with ErrNotFound.
func (s *Store) UnbindSubjectRole(subjectID, roleID, kind, value string) error {
	return s.closeOpen(tableSubjectRoles, s.writeInstant(), CloseRevoke,
		subjectID, roleID, kind, value)
}

// UpdateSubjectRoleScope closes the open interval for the old scoped binding
// and opens one carrying newScope at the same instant, which history reports as
// a single UPDATE instead of a revoke/grant pair. The new identity must not
// already be open.
func (s *Store) UpdateSubjectRoleScope(subjectID, roleID, oldKind, oldValue, newKind, newValue string) error {
	when := s.writeInstant()
	tx, err := s.db.Begin()
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback()

	openID, open, err := s.openIntervalIDTx(tx, tableSubjectRoles,
		subjectID, roleID, oldKind, oldValue)
	if err != nil {
		return err
	}
	if !open {
		return ErrNotFound
	}
	if oldKind == newKind && oldValue == newValue {
		return nil
	}
	if exists, err := s.openIdentityTx(tx, tableSubjectRoles,
		subjectID, roleID, newKind, newValue); err != nil {
		return err
	} else if exists {
		return ErrConflict
	}
	if _, err := tx.Exec(
		`UPDATE subject_role_intervals SET valid_to = ?, close_reason = ? WHERE id = ?`,
		when, CloseUpdate, openID); err != nil {
		return mapErr(err)
	}
	s.seq++
	if _, err := tx.Exec(
		`INSERT INTO subject_role_intervals
			(subject_id, role_id, scope_kind, scope_value, valid_from, valid_to, close_reason, seq)
			VALUES (?, ?, ?, ?, ?, NULL, '', ?)`,
		subjectID, roleID, newKind, newValue, when, s.seq); err != nil {
		return mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return mapErr(err)
	}
	return nil
}

// GrantDirect opens a new validity interval for a direct permission grant.
func (s *Store) GrantDirect(subjectID, permissionID, kind, value string) error {
	open, err := s.openVersion(tableDirectGrants, subjectID, permissionID, kind, value)
	if err != nil || open {
		if open {
			return ErrAlreadyOpen
		}
		return err
	}
	return s.insertVersion(tableDirectGrants, s.writeInstant(),
		subjectID, permissionID, kind, value)
}

// RevokeDirect closes the open interval for one scoped direct grant.
func (s *Store) RevokeDirect(subjectID, permissionID, kind, value string) error {
	return s.closeOpen(tableDirectGrants, s.writeInstant(), CloseRevoke,
		subjectID, permissionID, kind, value)
}

// AuthorizeRolePermission opens a new validity interval authorizing a
// permission point for a role.
func (s *Store) AuthorizeRolePermission(roleID, permissionID string) error {
	open, err := s.openVersion(tableRolePermissions, roleID, permissionID)
	if err != nil || open {
		if open {
			return ErrAlreadyOpen
		}
		return err
	}
	return s.insertVersion(tableRolePermissions, s.writeInstant(), roleID, permissionID)
}

// RevokeRolePermission closes the open interval that authorizes a permission
// point for a role.
func (s *Store) RevokeRolePermission(roleID, permissionID string) error {
	return s.closeOpen(tableRolePermissions, s.writeInstant(), CloseRevoke,
		roleID, permissionID)
}

func (s *Store) openIntervalIDTx(tx *sql.Tx, table string, identity ...any) (int64, bool, error) {
	definition, ok := intervalTables[table]
	if !ok {
		return 0, false, nil
	}
	var id, from, seq int64
	err := tx.QueryRow(definition.open, identity...).Scan(&id, &from, &seq)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, mapErr(err)
	}
	return id, true, nil
}

func (s *Store) openIdentityTx(tx *sql.Tx, table string, identity ...any) (bool, error) {
	_, exists, err := s.openIntervalIDTx(tx, table, identity...)
	return exists, err
}

// AddRoleInheritance records that roleID inherits from parentID. It rejects
// cycles, including the would-be cycle created by this edge.
func (s *Store) AddRoleInheritance(roleID, parentID string) error {
	cycle, err := s.wouldInheritanceCycle(roleID, parentID)
	if err != nil {
		return err
	}
	if cycle {
		return ErrConflict
	}
	return s.AddLink("role_inheritance", roleID, parentID)
}

// RemoveRoleInheritance deletes one inheritance edge.
func (s *Store) RemoveRoleInheritance(roleID, parentID string) error {
	return s.RemoveLink("role_inheritance", roleID, parentID)
}

func (s *Store) wouldInheritanceCycle(roleID, parentID string) (bool, error) {
	if roleID == parentID {
		return true, nil
	}
	visited := map[string]bool{roleID: true}
	frontier := []string{parentID}
	for len(frontier) > 0 {
		current := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if current == roleID {
			return true, nil
		}
		if visited[current] {
			continue
		}
		visited[current] = true
		parents, err := s.roleParents(current)
		if err != nil {
			return false, err
		}
		frontier = append(frontier, parents...)
	}
	return false, nil
}

func (s *Store) roleParents(roleID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT parent_id FROM role_inheritance WHERE role_id = ? ORDER BY parent_id ASC`,
		roleID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	parents := make([]string, 0)
	for rows.Next() {
		var parent string
		if err := rows.Scan(&parent); err != nil {
			return nil, mapErr(err)
		}
		parents = append(parents, parent)
	}
	return parents, mapErr(rows.Err())
}
