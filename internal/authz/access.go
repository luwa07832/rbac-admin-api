package authz

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// Access sources reported by the effective-access listing.
const (
	SourceRole             = "ROLE"
	SourceDirectPermission = "DIRECT_PERMISSION"
)

// AccessInput is the effective-access query: one subject at one moment.
type AccessInput struct {
	Subject     string
	EffectiveAt string
}

// AccessItem is one effective authorization path in public shape. Role-derived
// items keep the directly bound role alongside the inherited role carrying the
// permission; direct permission grants skip the role layer and leave both role
// fields null.
type AccessItem struct {
	Source     string   `json:"source"`
	BoundRole  *string  `json:"boundRole"`
	Role       *string  `json:"role"`
	Permission string   `json:"permission"`
	Operations []string `json:"operations"`
	Scope      string   `json:"scope"`
}

// Access lists the subject's authorization paths whose three interval layers
// all contain effectiveAt (defaulting to now). The query is read-only and an
// empty result is a normal outcome, never an error. A malformed effectiveAt
// is the one failure that outranks subject validation.
func (s *Service) Access(in AccessInput) ([]AccessItem, *Failure) {
	at := time.Now().UTC()
	if in.EffectiveAt != "" {
		parsed, fail := ParseTime(in.EffectiveAt)
		if fail != nil {
			return nil, fail
		}
		at = parsed
	}
	if !validIdentifier(in.Subject) {
		return nil, invalidRequest("subject", "field subject is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogSubject, in.Subject); err != nil || !exists {
		return nil, notFoundOrInternal("subject", err, !exists)
	}
	snap, err := s.loadSnapshot(in.Subject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate access")
	}
	return listAccess(snap, FormatTime(at)), nil
}

// listAccess flattens every authorization path active at the given instant:
// role-derived paths join an active binding, the inherited role's active
// permission grant and an active scope on that same role, while direct
// permission grants stand on their own. Overlapping interval versions of one
// identity collapse into a single item, and the result is ordered by the
// published field sequence.
func listAccess(snap *snapshot, at string) []AccessItem {
	boundRoles := map[string]bool{}
	for _, row := range snap.bindings {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) {
			boundRoles[row.roleID] = true
		}
	}
	reachableCache := map[string]map[string]bool{}
	reachableFrom := func(role string) map[string]bool {
		reachable, ok := reachableCache[role]
		if !ok {
			reachable = reachableRoles(map[string]bool{role: true}, snap.roleParents)
			reachableCache[role] = reachable
		}
		return reachable
	}
	activePairs := map[[2]string]bool{}
	for _, row := range snap.rolePerm {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) {
			activePairs[[2]string{row.roleID, row.permissionID}] = true
		}
	}

	items := []AccessItem{}
	seen := map[string]bool{}
	add := func(source, boundRole, role, permission, scope string) {
		operations := sortedOperations(snap.permOperations[permission])
		key := accessKey(source, boundRole, role, permission, operations, scope)
		if seen[key] {
			return
		}
		seen[key] = true
		items = append(items, AccessItem{
			Source:     source,
			BoundRole:  nullable(boundRole),
			Role:       nullable(role),
			Permission: permission,
			Operations: operations,
			Scope:      scope,
		})
	}

	for _, row := range snap.scopes {
		if !rowActive(row.effectiveFrom, row.effectiveTo, at) {
			continue
		}
		if row.permissionID != "" {
			add(SourceDirectPermission, "", "", row.permissionID, row.scope.text)
			continue
		}
		for pair := range activePairs {
			if pair[0] != row.roleID {
				continue
			}
			for boundRole := range boundRoles {
				if reachableFrom(boundRole)[row.roleID] {
					add(SourceRole, boundRole, row.roleID, pair[1], row.scope.text)
				}
			}
		}
	}

	sort.SliceStable(items, func(i, j int) bool { return accessLess(items[i], items[j]) })
	return items
}

// AccessDiffInput compares one subject's effective paths at two moments.
type AccessDiffInput struct {
	Subject string
	From    string
	To      string
}

// AccessDiffView holds the symmetric difference of the paths effective at
// the two moments; from and to carry the canonical UTC texts.
type AccessDiffView struct {
	From      string       `json:"from"`
	To        string       `json:"to"`
	Added     []AccessItem `json:"added"`
	Removed   []AccessItem `json:"removed"`
	Unchanged []AccessItem `json:"unchanged"`
}

// AccessDiff lists which of the subject's effective authorization paths were
// added, removed or kept between two moments. Both moments are mandatory and
// the query is read-only. Timing validation outranks subject validation, with
// from reported before to; equal moments are a normal request.
func (s *Service) AccessDiff(in AccessDiffInput) (*AccessDiffView, *Failure) {
	if in.From == "" {
		return nil, invalidRequest("from", "from query parameter is required")
	}
	if in.To == "" {
		return nil, invalidRequest("to", "to query parameter is required")
	}
	fromTime, fail := ParseTime(in.From)
	if fail != nil {
		fail.Field = "from"
		return nil, fail
	}
	toTime, fail := ParseTime(in.To)
	if fail != nil {
		fail.Field = "to"
		return nil, fail
	}
	if fromTime.After(toTime) {
		return nil, failure(TypeInvalidRange, "", "the range start must not be later than the range end")
	}
	if !validIdentifier(in.Subject) {
		return nil, invalidRequest("subject", "field subject is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogSubject, in.Subject); err != nil || !exists {
		return nil, notFoundOrInternal("subject", err, !exists)
	}

	snap, err := s.loadSnapshot(in.Subject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate access diff")
	}
	fromItems := listAccess(snap, FormatTime(fromTime))
	toItems := listAccess(snap, FormatTime(toTime))

	fromKeys := map[string]bool{}
	for _, item := range fromItems {
		fromKeys[itemKey(item)] = true
	}
	toKeys := map[string]bool{}
	for _, item := range toItems {
		toKeys[itemKey(item)] = true
	}

	view := &AccessDiffView{
		From:      FormatTime(fromTime),
		To:        FormatTime(toTime),
		Added:     []AccessItem{},
		Removed:   []AccessItem{},
		Unchanged: []AccessItem{},
	}
	// listAccess already deduplicates and orders both lists, so membership
	// filtering preserves the published ordering.
	for _, item := range toItems {
		if fromKeys[itemKey(item)] {
			view.Unchanged = append(view.Unchanged, item)
		} else {
			view.Added = append(view.Added, item)
		}
	}
	for _, item := range fromItems {
		if !toKeys[itemKey(item)] {
			view.Removed = append(view.Removed, item)
		}
	}
	return view, nil
}

// itemKey renders one effective path's full field combination for identity.
func itemKey(item AccessItem) string {
	return accessKey(item.Source, pointerText(item.BoundRole), pointerText(item.Role),
		item.Permission, item.Operations, item.Scope)
}

// accessKey joins the complete path combination with a field separator that no
// identifier or operation text can contain.
func accessKey(source, boundRole, role, permission string, operations []string, scope string) string {
	return strings.Join([]string{source, boundRole, role, permission, scope, strings.Join(operations, "\x00")}, "\x00")
}

// sortedOperations renders the permission's static operation set as a
// deduplicated list ordered by identifier.
func sortedOperations(operationSet map[string]bool) []string {
	operations := []string{}
	for operation := range operationSet {
		operations = append(operations, operation)
	}
	sort.Strings(operations)
	return operations
}

// accessLess orders items by source, boundRole, role, permission, operations
// and scope; absent role fields sort as empty text.
func accessLess(a, b AccessItem) bool {
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if pointerText(a.BoundRole) != pointerText(b.BoundRole) {
		return pointerText(a.BoundRole) < pointerText(b.BoundRole)
	}
	if pointerText(a.Role) != pointerText(b.Role) {
		return pointerText(a.Role) < pointerText(b.Role)
	}
	if a.Permission != b.Permission {
		return a.Permission < b.Permission
	}
	if cmp := slices.Compare(a.Operations, b.Operations); cmp != 0 {
		return cmp < 0
	}
	return a.Scope < b.Scope
}

func pointerText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
