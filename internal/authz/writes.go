package authz

import "github.com/luwa07832/rbac-admin-api/internal/store"

// RegisterInput registers an identifier in one of the static directories.
type RegisterInput struct {
	Kind store.CatalogKind
	ID   string
}

// Register inserts an identifier when it is missing; it is idempotent.
func (s *Service) Register(in RegisterInput) *Failure {
	if !validIdentifier(in.ID) {
		return invalidRequest("id", "field id is not a parseable identifier")
	}
	if err := s.store.EnsureCatalog(in.Kind, in.ID); err != nil {
		return failure(TypeInvalidRequest, "id", "could not register identifier")
	}
	return nil
}

// SetRoleParentsInput replaces the static parent set of a role.
type SetRoleParentsInput struct {
	RoleID  string
	Parents []string
}

// SetRoleParents updates static role inheritance.
func (s *Service) SetRoleParents(in SetRoleParentsInput) *Failure {
	if !validIdentifier(in.RoleID) {
		return invalidRequest("role", "field role is not a parseable identifier")
	}
	seen := map[string]bool{}
	for _, parent := range in.Parents {
		if !validIdentifier(parent) {
			return invalidRequest("parents", "parents must contain parseable identifiers")
		}
		if seen[parent] {
			return invalidRequest("parents", "parent listed more than once")
		}
		seen[parent] = true
	}
	return mapStoreError(s.store.SetRoleParents(in.RoleID, in.Parents))
}

// SetPermissionOperationsInput replaces the operation set of a permission.
type SetPermissionOperationsInput struct {
	PermissionID string
	Operations   []string
}

// SetPermissionOperations updates the static operations of a permission.
func (s *Service) SetPermissionOperations(in SetPermissionOperationsInput) *Failure {
	if !validIdentifier(in.PermissionID) {
		return invalidRequest("permission", "field permission is not a parseable identifier")
	}
	seen := map[string]bool{}
	for _, operation := range in.Operations {
		if !validIdentifier(operation) {
			return invalidRequest("operations", "operations must contain parseable identifiers")
		}
		if seen[operation] {
			return invalidRequest("operations", "operation listed more than once")
		}
		seen[operation] = true
	}
	return mapStoreError(s.store.SetPermissionOperations(in.PermissionID, in.Operations))
}

// LayerWrite carries the identity and timing of one versioned change.
type LayerWrite struct {
	Subject    string
	Role       string
	Permission string
	Scope      string

	OccurredAt    string
	EffectiveFrom string
}

func (s *Service) validateBinding(in LayerWrite) (timings, *Failure) {
	if !validIdentifier(in.Subject) {
		return timings{}, invalidRequest("subject", "field subject is not a parseable identifier")
	}
	if !validIdentifier(in.Role) {
		return timings{}, invalidRequest("role", "field role is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogSubject, in.Subject); err != nil || !exists {
		return timings{}, notFoundOrInternal("subject", err, !exists)
	}
	if exists, err := s.store.Exists(store.CatalogRole, in.Role); err != nil || !exists {
		return timings{}, notFoundOrInternal("role", err, !exists)
	}
	timingsValue, fail := s.resolveTimings(in.OccurredAt, in.EffectiveFrom, "effectiveFrom")
	return timingsValue, fail
}

func (s *Service) validateRolePermission(in LayerWrite) (timings, *Failure) {
	if !validIdentifier(in.Role) {
		return timings{}, invalidRequest("role", "field role is not a parseable identifier")
	}
	if !validIdentifier(in.Permission) {
		return timings{}, invalidRequest("permission", "field permission is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogRole, in.Role); err != nil || !exists {
		return timings{}, notFoundOrInternal("role", err, !exists)
	}
	if exists, err := s.store.Exists(store.CatalogPermission, in.Permission); err != nil || !exists {
		return timings{}, notFoundOrInternal("permission", err, !exists)
	}
	return s.resolveTimings(in.OccurredAt, in.EffectiveFrom, "effectiveFrom")
}

func (s *Service) validateScope(in LayerWrite) (timings, *Failure) {
	if !validIdentifier(in.Subject) {
		return timings{}, invalidRequest("subject", "field subject is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogSubject, in.Subject); err != nil || !exists {
		return timings{}, notFoundOrInternal("subject", err, !exists)
	}
	switch {
	case in.Role != "" && in.Permission != "":
		return timings{}, invalidRequest("role", "set exactly one of role or permission")
	case in.Role == "" && in.Permission == "":
		return timings{}, invalidRequest("role", "set exactly one of role or permission")
	case in.Role != "":
		if !validIdentifier(in.Role) {
			return timings{}, invalidRequest("role", "field role is not a parseable identifier")
		}
		if exists, err := s.store.Exists(store.CatalogRole, in.Role); err != nil || !exists {
			return timings{}, notFoundOrInternal("role", err, !exists)
		}
	default:
		if !validIdentifier(in.Permission) {
			return timings{}, invalidRequest("permission", "field permission is not a parseable identifier")
		}
		if exists, err := s.store.Exists(store.CatalogPermission, in.Permission); err != nil || !exists {
			return timings{}, notFoundOrInternal("permission", err, !exists)
		}
	}
	if _, ok := parseScope(in.Scope); !ok {
		return timings{}, invalidRequest("scope", "scope is not a parseable authorization boundary")
	}
	return s.resolveTimings(in.OccurredAt, in.EffectiveFrom, "effectiveFrom")
}

func notFoundOrInternal(field string, err error, missing bool) *Failure {
	if err != nil {
		return failure(TypeInvalidRequest, field, "could not verify "+field)
	}
	if missing {
		return failure(TypeNotFound, field, field+" does not exist")
	}
	return nil
}

func mapStoreError(err error) *Failure {
	if err == nil {
		return nil
	}
	if storeErr, ok := err.(*store.Error); ok {
		return &Failure{Type: storeErr.Type, Field: storeErr.Field, Message: storeErr.Message}
	}
	return failure(TypeInvalidRequest, "", "could not apply the change")
}

// GrantBinding opens a new subject/role binding interval.
func (s *Service) GrantBinding(in LayerWrite) *Failure {
	timingsValue, fail := s.validateBinding(in)
	if fail != nil {
		return fail
	}
	return mapStoreError(s.store.GrantBinding(in.Subject, in.Role, timingsValue.occurredAt, timingsValue.effectiveFrom))
}

// UpdateBinding moves the open binding from one role to another.
func (s *Service) UpdateBinding(oldRole LayerWrite, newRole LayerWrite) *Failure {
	oldTimings, fail := s.validateBinding(oldRole)
	if fail != nil {
		return fail
	}
	if !validIdentifier(newRole.Role) {
		return invalidRequest("newRole", "field newRole is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogRole, newRole.Role); err != nil || !exists {
		return notFoundOrInternal("newRole", err, !exists)
	}
	return mapStoreError(s.store.UpdateBinding(oldRole.Subject, oldRole.Role, newRole.Role,
		oldTimings.occurredAt, oldTimings.effectiveFrom))
}

// RevokeBinding closes the open subject/role binding interval.
func (s *Service) RevokeBinding(in LayerWrite) *Failure {
	timingsValue, fail := s.validateBinding(in)
	if fail != nil {
		return fail
	}
	return mapStoreError(s.store.RevokeBinding(in.Subject, in.Role, timingsValue.occurredAt, timingsValue.effectiveFrom))
}

// GrantRolePermission opens a new role/permission interval.
func (s *Service) GrantRolePermission(in LayerWrite) *Failure {
	timingsValue, fail := s.validateRolePermission(in)
	if fail != nil {
		return fail
	}
	return mapStoreError(s.store.GrantRolePermission(in.Role, in.Permission, timingsValue.occurredAt, timingsValue.effectiveFrom))
}

// UpdateRolePermission moves the open interval to a new role/permission pair.
func (s *Service) UpdateRolePermission(oldPair, newPair LayerWrite) *Failure {
	oldTimings, fail := s.validateRolePermission(oldPair)
	if fail != nil {
		return fail
	}
	if !validIdentifier(newPair.Role) || !validIdentifier(newPair.Permission) {
		return invalidRequest("newTarget", "new role and permission must be parseable identifiers")
	}
	if exists, err := s.store.Exists(store.CatalogRole, newPair.Role); err != nil || !exists {
		return notFoundOrInternal("newRole", err, !exists)
	}
	if exists, err := s.store.Exists(store.CatalogPermission, newPair.Permission); err != nil || !exists {
		return notFoundOrInternal("newPermission", err, !exists)
	}
	return mapStoreError(s.store.UpdateRolePermission(oldPair.Role, oldPair.Permission,
		newPair.Role, newPair.Permission, oldTimings.occurredAt, oldTimings.effectiveFrom))
}

// RevokeRolePermission closes the open role/permission interval.
func (s *Service) RevokeRolePermission(in LayerWrite) *Failure {
	timingsValue, fail := s.validateRolePermission(in)
	if fail != nil {
		return fail
	}
	return mapStoreError(s.store.RevokeRolePermission(in.Role, in.Permission, timingsValue.occurredAt, timingsValue.effectiveFrom))
}

// GrantScope opens a new scoped authorization interval.
func (s *Service) GrantScope(in LayerWrite) *Failure {
	timingsValue, fail := s.validateScope(in)
	if fail != nil {
		return fail
	}
	return mapStoreError(s.store.GrantScope(in.Subject, in.Role, in.Permission, in.Scope,
		timingsValue.occurredAt, timingsValue.effectiveFrom))
}

// UpdateScope moves the open interval to a new scope identity.
func (s *Service) UpdateScope(oldScope, newScope LayerWrite) *Failure {
	oldTimings, fail := s.validateScope(oldScope)
	if fail != nil {
		return fail
	}
	if (newScope.Role == "") == (newScope.Permission == "") {
		return invalidRequest("newTarget", "set exactly one of new role or permission")
	}
	if newScope.Role != "" {
		if !validIdentifier(newScope.Role) {
			return invalidRequest("newRole", "field newRole is not a parseable identifier")
		}
		if exists, err := s.store.Exists(store.CatalogRole, newScope.Role); err != nil || !exists {
			return notFoundOrInternal("newRole", err, !exists)
		}
	} else {
		if !validIdentifier(newScope.Permission) {
			return invalidRequest("newPermission", "field newPermission is not a parseable identifier")
		}
		if exists, err := s.store.Exists(store.CatalogPermission, newScope.Permission); err != nil || !exists {
			return notFoundOrInternal("newPermission", err, !exists)
		}
	}
	if _, ok := parseScope(newScope.Scope); !ok {
		return invalidRequest("newScope", "scope is not a parseable authorization boundary")
	}
	return mapStoreError(s.store.UpdateScope(oldScope.Subject,
		oldScope.Role, oldScope.Permission, oldScope.Scope,
		newScope.Role, newScope.Permission, newScope.Scope,
		oldTimings.occurredAt, oldTimings.effectiveFrom))
}

// RevokeScope closes the open scoped authorization interval.
func (s *Service) RevokeScope(in LayerWrite) *Failure {
	timingsValue, fail := s.validateScope(in)
	if fail != nil {
		return fail
	}
	return mapStoreError(s.store.RevokeScope(in.Subject, in.Role, in.Permission, in.Scope,
		timingsValue.occurredAt, timingsValue.effectiveFrom))
}
