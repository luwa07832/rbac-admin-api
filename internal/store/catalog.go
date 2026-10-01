package store

import "database/sql"

// CatalogKind identifies one of the static directories.
type CatalogKind string

const (
	CatalogSubject    CatalogKind = "subject"
	CatalogResource   CatalogKind = "resource"
	CatalogOperation  CatalogKind = "operation"
	CatalogRole       CatalogKind = "role"
	CatalogPermission CatalogKind = "permission"
)

// EnsureCatalog inserts id into the directory when it is missing. It is
// idempotent: re-registering an existing id is a successful no-op.
func (s *Store) EnsureCatalog(kind CatalogKind, id string) error {
	switch kind {
	case CatalogSubject, CatalogResource, CatalogOperation, CatalogRole, CatalogPermission:
	default:
		return apiError(TypeInvalidRequest, string(kind), "unknown catalog kind")
	}
	if _, err := s.db.Exec("INSERT OR IGNORE INTO "+tableForCatalog(kind)+" (id) VALUES (?)", id); err != nil {
		return apiError(TypeInvalidRequest, string(kind), "could not register identifier")
	}
	return nil
}

func tableForCatalog(kind CatalogKind) string {
	switch kind {
	case CatalogSubject:
		return "subjects"
	case CatalogResource:
		return "resources"
	case CatalogOperation:
		return "operations"
	case CatalogRole:
		return "roles"
	default:
		return "permissions"
	}
}

// Exists reports whether id is present in the given directory.
func (s *Store) Exists(kind CatalogKind, id string) (bool, error) {
	var count int
	if err := s.db.QueryRow(
		"SELECT COUNT(1) FROM "+tableForCatalog(kind)+" WHERE id = ?", id,
	).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// RoleParents returns the parent roles configured for roleID in stored order.
func (s *Store) RoleParents(roleID string) ([]string, error) {
	rows, err := s.db.Query(
		"SELECT parent_id FROM role_parents WHERE role_id = ? ORDER BY position", roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var parents []string
	for rows.Next() {
		var parent string
		if err := rows.Scan(&parent); err != nil {
			return nil, err
		}
		parents = append(parents, parent)
	}
	return parents, rows.Err()
}

// SetRoleParents replaces the parent set of roleID. The role and every parent
// must already be registered; a cyclic inheritance graph is rejected.
func (s *Store) SetRoleParents(roleID string, parents []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := requireRow(tx, "roles", roleID, CatalogRole); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, parent := range parents {
		if parent == roleID || seen[parent] {
			return apiError(TypeInvalidRequest, "parents", "role inheritance is invalid: duplicated or self-referencing parent")
		}
		seen[parent] = true
		ok, err := existsInTx(tx, "roles", parent)
		if err != nil {
			return err
		}
		if !ok {
			return apiError(TypeNotFound, "role", "role "+parent+" does not exist")
		}
	}
	if err := detectRoleCycle(tx, roleID, parents); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM role_parents WHERE role_id = ?", roleID); err != nil {
		return err
	}
	for position, parent := range parents {
		if _, err := tx.Exec(
			"INSERT INTO role_parents (role_id, parent_id, position) VALUES (?, ?, ?)",
			roleID, parent, position); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PermissionOperations returns the operations covered by permissionID.
func (s *Store) PermissionOperations(permissionID string) ([]string, error) {
	rows, err := s.db.Query(
		"SELECT operation_id FROM permission_operations WHERE permission_id = ? ORDER BY position", permissionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var operations []string
	for rows.Next() {
		var operation string
		if err := rows.Scan(&operation); err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	return operations, rows.Err()
}

// SetPermissionOperations replaces the operation set of permissionID. The
// permission and every operation must already be registered.
func (s *Store) SetPermissionOperations(permissionID string, operations []string) error {
	if len(operations) == 0 {
		return apiError(TypeInvalidRequest, "operations", "permission must cover at least one operation")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := requireRow(tx, "permissions", permissionID, CatalogPermission); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, operation := range operations {
		if seen[operation] {
			return apiError(TypeInvalidRequest, "operations", "operation listed more than once")
		}
		seen[operation] = true
		ok, err := existsInTx(tx, "operations", operation)
		if err != nil {
			return err
		}
		if !ok {
			return apiError(TypeNotFound, "operation", "operation "+operation+" does not exist")
		}
	}
	if _, err := tx.Exec("DELETE FROM permission_operations WHERE permission_id = ?", permissionID); err != nil {
		return err
	}
	for position, operation := range operations {
		if _, err := tx.Exec(
			"INSERT INTO permission_operations (permission_id, operation_id, position) VALUES (?, ?, ?)",
			permissionID, operation, position); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func requireRow(tx *sql.Tx, table, id string, kind CatalogKind) error {
	ok, err := existsInTx(tx, table, id)
	if err != nil {
		return err
	}
	if !ok {
		return apiError(TypeNotFound, string(kind), string(kind)+" does not exist")
	}
	return nil
}

func existsInTx(tx *sql.Tx, table, id string) (bool, error) {
	var count int
	if err := tx.QueryRow("SELECT COUNT(1) FROM "+table+" WHERE id = ?", id).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// detectRoleCycle rejects an update whose parent set would create an
// inheritance cycle reachable from roleID.
func detectRoleCycle(tx *sql.Tx, roleID string, parents []string) error {
	adjacency := map[string][]string{roleID: parents}
	loadParents := func(role string) ([]string, error) {
		if cached, ok := adjacency[role]; ok {
			return cached, nil
		}
		rows, err := tx.Query("SELECT parent_id FROM role_parents WHERE role_id = ? ORDER BY position", role)
		if err != nil {
			return nil, err
		}
		var result []string
		for rows.Next() {
			var parent string
			if err := rows.Scan(&parent); err != nil {
				rows.Close()
				return nil, err
			}
			result = append(result, parent)
		}
		rows.Close()
		adjacency[role] = result
		return result, rows.Err()
	}

	const inStack, done = 1, 2
	state := map[string]int{}
	var walk func(string) error
	walk = func(role string) error {
		switch state[role] {
		case inStack:
			return apiError(TypeInvalidRequest, "parents", "role inheritance forms a cycle")
		case done:
			return nil
		}
		state[role] = inStack
		current, err := loadParents(role)
		if err != nil {
			return err
		}
		for _, parent := range current {
			if err := walk(parent); err != nil {
				return err
			}
		}
		state[role] = done
		return nil
	}
	return walk(roleID)
}

// ListCatalog returns every identifier registered in a directory.
func (s *Store) ListCatalog(kind CatalogKind) ([]string, error) {
	rows, err := s.db.Query("SELECT id FROM " + tableForCatalog(kind) + " ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
