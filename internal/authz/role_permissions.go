package authz

import (
	"slices"
	"sort"
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// Sources reported by the role-permissions listing. Grants carried by the
// target role itself are DIRECT; grants on an ancestor role are INHERITED.
const (
	SourceDirect    = "DIRECT"
	SourceInherited = "INHERITED"
)

// RolePermissionsInput is the read-only role definition query: one role at
// one moment. Role inheritance always uses the current graph; only role and
// permission grants are filtered by effectiveAt.
type RolePermissionsInput struct {
	Role        string
	EffectiveAt string
}

// RolePermissionItem is one effective permission point of the queried role.
type RolePermissionItem struct {
	Role       string   `json:"role"`
	Permission string   `json:"permission"`
	Operations []string `json:"operations"`
	Source     string   `json:"source"`
}

// RolePermissionsView is the public shape of GET /roles/{role}/permissions.
// Every collection is rendered as an array, even when empty.
type RolePermissionsView struct {
	EffectiveAt    string               `json:"effectiveAt"`
	Role           string               `json:"role"`
	Parents        []string             `json:"parents"`
	InheritedRoles []string             `json:"inheritedRoles"`
	Permissions    []RolePermissionItem `json:"permissions"`
}

// RolePermissions expands one role's permission composition at effectiveAt
// (defaulting to now). The query is strictly read-only: it never creates
// interval versions or history rows. A malformed effectiveAt is the one
// failure that outranks role validation.
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
	rows, err := s.loadRolePermissionRows()
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate role permissions")
	}
	model, err := s.loadRoleModel()
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate role permissions")
	}
	view := buildRolePermissionsView(in.Role, rows, model, FormatTime(at))
	return view, nil
}

// buildRolePermissionsView walks the current inheritance graph from role and
// expands the role/permission grants active at at. Parent and ancestor lists
// come from the current graph without time filtering; only the grants are
// interval-filtered. The target role itself is never part of either list.
func buildRolePermissionsView(role string, rows []rolePermRow, model roleModel, at string) *RolePermissionsView {
	parents := append([]string{}, model.roleParents[role]...)
	sort.Strings(parents)

	reachable := reachableRoles(map[string]bool{role: true}, model.roleParents)
	ancestors := []string{}
	for ancestor := range reachable {
		if ancestor != role {
			ancestors = append(ancestors, ancestor)
		}
	}
	sort.Strings(ancestors)

	activePairs := map[[2]string]bool{}
	for _, row := range rows {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) {
			activePairs[[2]string{row.roleID, row.permissionID}] = true
		}
	}

	items := []RolePermissionItem{}
	for pair := range activePairs {
		carryingRole, permission := pair[0], pair[1]
		source := ""
		if carryingRole == role {
			source = SourceDirect
		} else if reachable[carryingRole] {
			source = SourceInherited
		}
		if source == "" {
			continue
		}
		items = append(items, RolePermissionItem{
			Role:       carryingRole,
			Permission: permission,
			Operations: sortedOperations(model.permOperations[permission]),
			Source:     source,
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Role != items[j].Role {
			return items[i].Role < items[j].Role
		}
		if items[i].Permission != items[j].Permission {
			return items[i].Permission < items[j].Permission
		}
		return slices.Compare(items[i].Operations, items[j].Operations) < 0
	})

	return &RolePermissionsView{
		EffectiveAt:    at,
		Role:           role,
		Parents:        parents,
		InheritedRoles: ancestors,
		Permissions:    items,
	}
}
