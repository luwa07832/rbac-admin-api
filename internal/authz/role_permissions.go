package authz

import (
	"sort"
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// Sources reported for one role-permission entry. A grant carried by the
// queried role itself is DIRECT; a grant reached through current inheritance
// is INHERITED.
const (
	SourceDirect    = "DIRECT"
	SourceInherited = "INHERITED"
)

// RolePermissionsInput is the read-only role-definition query: one role at one
// moment.
type RolePermissionsInput struct {
	Role        string
	EffectiveAt string
}

// RolePermissionItem is one permission point effective for the role at the
// queried instant. Role names the role that carries the grant, which may be
// the queried role itself or one of its ancestors.
type RolePermissionItem struct {
	Role       string   `json:"role"`
	Permission string   `json:"permission"`
	Operations []string `json:"operations"`
	Source     string   `json:"source"`
}

// RolePermissionsView is the public role composition. Parents and inherited
// roles always render as arrays, even when empty.
type RolePermissionsView struct {
	EffectiveAt    string                `json:"effectiveAt"`
	Role           string                `json:"role"`
	Parents        []string              `json:"parents"`
	InheritedRoles []string              `json:"inheritedRoles"`
	Permissions    []RolePermissionItem  `json:"permissions"`
}

// RolePermissions reads the current inheritance graph and the role/permission
// grants active at effectiveAt (defaulting to now). It performs no writes and
// records no history. A malformed effectiveAt outranks role validation.
func (s *Service) RolePermissions(in RolePermissionsInput) (*RolePermissionsView, *Failure) {
	at := time.Now().UTC()
	if in.EffectiveAt != "" {
		parsed, fail := ParseTime(in.EffectiveAt)
		if fail != nil {
			return nil, fail
		}
		at = parsed
	}
	if !validIdentifier(in.Role) {
		return nil, invalidRequest("role", "field role is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogRole, in.Role); err != nil || !exists {
		return nil, notFoundOrInternal("role", err, !exists)
	}

	roleParents, fail := s.loadRoleParentsMap()
	if fail != nil {
		return nil, fail
	}
	permOperations, fail := s.loadPermOperationsMap()
	if fail != nil {
		return nil, fail
	}
	rows, fail := s.loadRolePermRows()
	if fail != nil {
		return nil, fail
	}
	snap := &snapshot{
		rolePerm:       rows,
		roleParents:    roleParents,
		permOperations: permOperations,
	}
	parents, inherited, items := listRolePermissions(snap, in.Role, FormatTime(at))
	return &RolePermissionsView{
		EffectiveAt:    FormatTime(at),
		Role:           in.Role,
		Parents:        parents,
		InheritedRoles: inherited,
		Permissions:    items,
	}, nil
}

// listRolePermissions expands the role's current ancestors and the permission
// grants active at atText on the role itself (DIRECT) or any ancestor
// (INHERITED). Inheritance has no interval dimension, so the current parent
// graph is used unchanged.
func listRolePermissions(snap *snapshot, role, at string) ([]string, []string, []RolePermissionItem) {
	parents := sortedStringSet(snap.roleParents[role])
	ancestors := reachableRoles(map[string]bool{role: true}, snap.roleParents)
	delete(ancestors, role)
	inherited := sortedSet(ancestors)

	activePairs := map[[2]string]bool{}
	for _, row := range snap.rolePerm {
		if !rowActive(row.effectiveFrom, row.effectiveTo, at) {
			continue
		}
		if row.roleID != role && !ancestors[row.roleID] {
			continue
		}
		activePairs[[2]string{row.roleID, row.permissionID}] = true
	}

	items := []RolePermissionItem{}
	for pair := range activePairs {
		source := SourceInherited
		if pair[0] == role {
			source = SourceDirect
		}
		items = append(items, RolePermissionItem{
			Role:       pair[0],
			Permission: pair[1],
			Operations: sortedOperations(snap, pair[1]),
			Source:     source,
		})
	}
	sort.SliceStable(items, func(i, j int) bool { return rolePermissionItemLess(items[i], items[j]) })
	return parents, inherited, items
}

// rolePermissionItemLess orders items by carrying role, permission and the
// static operation set; source follows from the role and needs no tiebreak.
func rolePermissionItemLess(a, b RolePermissionItem) bool {
	if a.Role != b.Role {
		return a.Role < b.Role
	}
	if a.Permission != b.Permission {
		return a.Permission < b.Permission
	}
	return slicesCompare(a.Operations, b.Operations) < 0
}

// sortedStringSet returns values deduplicated and ordered by identifier.
func sortedStringSet(values []string) []string {
	return sortedSet(stringSet(values))
}

// sortedSet renders a set as a deduplicated list ordered by identifier.
func sortedSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func stringSet(values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		result[value] = true
	}
	return result
}

func slicesCompare(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}
