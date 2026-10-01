package store

import (
	"database/sql"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
)

// Snapshot loads every versioned relation row the temporal evaluator needs,
// including closed intervals so history can be rebuilt. Role definitions
// (inheritance and permission/operation coverage) are static and global.
func (s *Store) Snapshot(subjectID string) (authz.Data, error) {
	var data authz.Data

	bindingRows, err := s.db.Query(
		`SELECT role_id, scope_kind, scope_value, valid_from, valid_to, close_reason, seq
		 FROM subject_role_intervals WHERE subject_id = ?
		 ORDER BY valid_from ASC, seq ASC`, subjectID)
	if err != nil {
		return data, mapErr(err)
	}
	for bindingRows.Next() {
		var row authz.RoleVersion
		var to sql.NullInt64
		if err := bindingRows.Scan(&row.Role, &row.Scope.Kind, &row.Scope.Value,
			&row.From, &to, &row.CloseReason, &row.Seq); err != nil {
			bindingRows.Close()
			return data, mapErr(err)
		}
		if to.Valid {
			row.To, row.HasTo = to.Int64, true
		}
		data.RoleVersions = append(data.RoleVersions, row)
	}
	if err := bindingRows.Close(); err != nil {
		return data, mapErr(err)
	}

	grantRows, err := s.db.Query(
		`SELECT permission_id, scope_kind, scope_value, valid_from, valid_to, close_reason, seq
		 FROM direct_grant_intervals WHERE subject_id = ?
		 ORDER BY valid_from ASC, seq ASC`, subjectID)
	if err != nil {
		return data, mapErr(err)
	}
	for grantRows.Next() {
		var row authz.GrantVersion
		var to sql.NullInt64
		if err := grantRows.Scan(&row.Permission, &row.Scope.Kind, &row.Scope.Value,
			&row.From, &to, &row.CloseReason, &row.Seq); err != nil {
			grantRows.Close()
			return data, mapErr(err)
		}
		if to.Valid {
			row.To, row.HasTo = to.Int64, true
		}
		data.GrantVersions = append(data.GrantVersions, row)
	}
	if err := grantRows.Close(); err != nil {
		return data, mapErr(err)
	}

	rolePermRows, err := s.db.Query(
		`SELECT role_id, permission_id, valid_from, valid_to, close_reason, seq
		 FROM role_permission_intervals ORDER BY valid_from ASC, seq ASC`)
	if err != nil {
		return data, mapErr(err)
	}
	for rolePermRows.Next() {
		var row authz.RolePermissionVersion
		var to sql.NullInt64
		if err := rolePermRows.Scan(&row.Role, &row.Permission,
			&row.From, &to, &row.CloseReason, &row.Seq); err != nil {
			rolePermRows.Close()
			return data, mapErr(err)
		}
		if to.Valid {
			row.To, row.HasTo = to.Int64, true
		}
		data.RolePermissionVersions = append(data.RolePermissionVersions, row)
	}
	if err := rolePermRows.Close(); err != nil {
		return data, mapErr(err)
	}

	parentRows, err := s.db.Query(
		`SELECT role_id, parent_id FROM role_inheritance ORDER BY role_id ASC, parent_id ASC`)
	if err != nil {
		return data, mapErr(err)
	}
	for parentRows.Next() {
		var edge authz.RoleParent
		if err := parentRows.Scan(&edge.Role, &edge.Parent); err != nil {
			parentRows.Close()
			return data, mapErr(err)
		}
		data.RoleParents = append(data.RoleParents, edge)
	}
	if err := parentRows.Close(); err != nil {
		return data, mapErr(err)
	}

	permOpRows, err := s.db.Query(
		`SELECT permission_id, operation_id FROM permission_operations
		 ORDER BY permission_id ASC, operation_id ASC`)
	if err != nil {
		return data, mapErr(err)
	}
	for permOpRows.Next() {
		var link authz.PermissionOperation
		if err := permOpRows.Scan(&link.Permission, &link.Operation); err != nil {
			permOpRows.Close()
			return data, mapErr(err)
		}
		data.PermissionOperations = append(data.PermissionOperations, link)
	}
	if err := permOpRows.Close(); err != nil {
		return data, mapErr(err)
	}

	return data, nil
}
