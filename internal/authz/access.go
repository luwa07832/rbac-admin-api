package authz

import (
	"sort"
	"strings"
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// Source values for an effective authorization path.
const (
	SourceRole             = "ROLE"
	SourceDirectPermission = "DIRECT_PERMISSION"
)

// AccessInput is the read-only effective authorization listing query.
type AccessInput struct {
	Subject     string `json:"-"`
	EffectiveAt string `json:"-"`
}

// AccessEntry is one authorization path effective at the queried time.
// BoundRole and Role are null for DIRECT_PERMISSION entries; Operations is
// always emitted as an array.
type AccessEntry struct {
	Source     string   `json:"source"`
	BoundRole  *string  `json:"boundRole"`
	Role       *string  `json:"role"`
	Permission string   `json:"permission"`
	Operations []string `json:"operations"`
	Scope      string   `json:"scope"`
}

// Access lists every authorization path of the subject whose binding,
// role/permission grant and scope intervals all contain effectiveAt (which
// defaults to now). It performs no writes.
func (s *Service) Access(in AccessInput) ([]AccessEntry, *Failure) {
	if !validIdentifier(in.Subject) {
		return nil, invalidRequest("subject", "field subject is not a parseable identifier")
	}
	at := time.Now().UTC()
	if in.EffectiveAt != "" {
		parsed, fail := ParseTime(in.EffectiveAt)
		if fail != nil {
			fail.Field = "effectiveAt"
			return nil, fail
		}
		at = parsed
	}
	exists, err := s.store.Exists(store.CatalogSubject, in.Subject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "subject", "could not verify subject")
	}
	if !exists {
		return nil, failure(TypeNotFound, "subject", "subject does not exist")
	}

	snap, err := s.loadSnapshot(in.Subject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "subject", "could not evaluate authorization")
	}
	return collectAccess(snap, FormatTime(at)), nil
}

// accessKey identifies one distinct output tuple. The operation set is
// already sorted and joined so identical sets dedupe as one.
type accessKey struct {
	source     string
	boundRole  string
	role       string
	permission string
	opsKey     string
	scope      string
}

// collectAccess enumerates the three-layer-effective paths at at.
func collectAccess(snap *snapshot, at string) []AccessEntry {
	boundRoles := map[string]bool{}
	for _, row := range snap.bindings {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) {
			boundRoles[row.roleID] = true
		}
	}

	activeRolePerms := map[[2]string]bool{}
	for _, row := range snap.rolePerm {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) {
			activeRolePerms[[2]string{row.roleID, row.permissionID}] = true
		}
	}

	// carriersByRole maps a carrying role to every directly bound role that
	// reaches it through inheritance (including identical binding/carrying
	// roles), in identifier order.
	carriersByRole := map[string][]string{}
	for boundRole := range boundRoles {
		reachable := reachableRoles(map[string]bool{boundRole: true}, snap.roleParents)
		for carryingRole := range reachable {
			carriersByRole[carryingRole] = append(carriersByRole[carryingRole], boundRole)
		}
	}
	for role := range carriersByRole {
		sort.Strings(carriersByRole[role])
	}

	operationsCache := map[string][]string{}
	operationsFor := func(permissionID string) []string {
		if cached, ok := operationsCache[permissionID]; ok {
			return cached
		}
		operations := make([]string, 0, len(snap.permOperations[permissionID]))
		for operation := range snap.permOperations[permissionID] {
			operations = append(operations, operation)
		}
		sort.Strings(operations)
		operationsCache[permissionID] = operations
		return operations
	}

	entries := []AccessEntry{}
	seen := map[accessKey]bool{}
	add := func(entry AccessEntry) {
		key := accessKey{
			source:     entry.Source,
			permission: entry.Permission,
			opsKey:     strings.Join(entry.Operations, "\x00"),
			scope:      entry.Scope,
		}
		if entry.BoundRole != nil {
			key.boundRole = *entry.BoundRole
		}
		if entry.Role != nil {
			key.role = *entry.Role
		}
		if seen[key] {
			return
		}
		seen[key] = true
		entries = append(entries, entry)
	}

	for _, row := range snap.scopes {
		if !rowActive(row.effectiveFrom, row.effectiveTo, at) {
			continue
		}
		operations := operationsFor(row.permissionID)
		if row.permissionID != "" {
			add(AccessEntry{
				Source:     SourceDirectPermission,
				Permission: row.permissionID,
				Operations: operations,
				Scope:      row.scope.text,
			})
			continue
		}
		for pair := range activeRolePerms {
			if pair[0] != row.roleID {
				continue
			}
			for _, boundRole := range carriersByRole[row.roleID] {
				bound := boundRole
				carrier := row.roleID
				add(AccessEntry{
					Source:     SourceRole,
					BoundRole:  &bound,
					Role:       &carrier,
					Permission: pair[1],
					Operations: operationsFor(pair[1]),
					Scope:      row.scope.text,
				})
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool { return accessEntryLess(entries[i], entries[j]) })
	return entries
}

// accessEntryLess orders by source, boundRole, role, permission, the
// operation set in element order, then scope. Null roles sort after set ones
// (DIRECT_PERMISSION rows only appear after ROLE rows by source anyway).
func accessEntryLess(a, b AccessEntry) bool {
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if cmp := compareNullableString(a.BoundRole, b.BoundRole); cmp != 0 {
		return cmp < 0
	}
	if cmp := compareNullableString(a.Role, b.Role); cmp != 0 {
		return cmp < 0
	}
	if a.Permission != b.Permission {
		return a.Permission < b.Permission
	}
	if cmp := compareStringSets(a.Operations, b.Operations); cmp != 0 {
		return cmp < 0
	}
	return a.Scope < b.Scope
}

func compareNullableString(a, b *string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	case *a == *b:
		return 0
	case *a < *b:
		return -1
	default:
		return 1
	}
}

func compareStringSets(a, b []string) int {
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
