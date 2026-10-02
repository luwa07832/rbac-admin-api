package authz

import (
	"sort"
	"strings"
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// ResourceSubjectsInput is the reverse lookup: every subject granted one
// resource/operation pair at one moment.
type ResourceSubjectsInput struct {
	Resource    string
	Operation   string
	EffectiveAt string
}

// SubjectPath is one effective authorization path in public shape, mirroring
// the access listing minus the operation set: the queried operation is fixed.
type SubjectPath struct {
	Source     string  `json:"source"`
	BoundRole  *string `json:"boundRole"`
	Role       *string `json:"role"`
	Permission string  `json:"permission"`
	Scope      string  `json:"scope"`
}

// ResourceSubjectItem groups one subject's deduplicated grant paths.
type ResourceSubjectItem struct {
	Subject string        `json:"subject"`
	Paths   []SubjectPath `json:"paths"`
}

// ResourceSubjectsView is the public shape of
// GET /resources/{resource}/subjects. The subject collection renders as an
// array even when empty.
type ResourceSubjectsView struct {
	EffectiveAt string                `json:"effectiveAt"`
	Resource    string                `json:"resource"`
	Operation   string                `json:"operation"`
	Subjects    []ResourceSubjectItem `json:"subjects"`
}

// ResourceSubjects lists every subject with at least one authorization path
// whose three interval layers all contain effectiveAt (defaulting to now).
// The query is strictly read-only and an empty result is a normal outcome,
// never an error. A malformed effectiveAt is the one failure that outranks
// resource and operation validation.
func (s *Service) ResourceSubjects(in ResourceSubjectsInput) (*ResourceSubjectsView, *Failure) {
	at := time.Now().UTC()
	if in.EffectiveAt != "" {
		parsed, fail := ParseTime(in.EffectiveAt)
		if fail != nil {
			return nil, fail
		}
		at = parsed
	}
	if !validIdentifier(in.Resource) {
		return nil, invalidRequest("resource", "field resource is not a parseable identifier")
	}
	if in.Operation == "" {
		return nil, invalidRequest("operation", "operation query parameter is required")
	}
	if !validIdentifier(in.Operation) {
		return nil, invalidRequest("operation", "field operation is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogResource, in.Resource); err != nil || !exists {
		return nil, notFoundOrInternal("resource", err, !exists)
	}
	if exists, err := s.store.Exists(store.CatalogOperation, in.Operation); err != nil || !exists {
		return nil, notFoundOrInternal("operation", err, !exists)
	}

	rolePermRows, err := s.loadRolePermissionRows()
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects")
	}
	model, err := s.loadRoleModel()
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects")
	}
	subjectIDs, err := s.store.ListCatalog(store.CatalogSubject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects")
	}

	view := &ResourceSubjectsView{
		EffectiveAt: FormatTime(at),
		Resource:    in.Resource,
		Operation:   in.Operation,
		Subjects:    []ResourceSubjectItem{},
	}
	atText := FormatTime(at)
	for _, subjectID := range subjectIDs {
		bindings, scopes, err := s.loadSubjectRows(subjectID)
		if err != nil {
			return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects")
		}
		paths := subjectGrantPaths(bindings, scopes, rolePermRows, model, in.Resource, in.Operation, atText)
		if len(paths) == 0 {
			continue
		}
		view.Subjects = append(view.Subjects, ResourceSubjectItem{Subject: subjectID, Paths: paths})
	}
	sort.SliceStable(view.Subjects, func(i, j int) bool {
		return view.Subjects[i].Subject < view.Subjects[j].Subject
	})
	return view, nil
}

// subjectGrantPaths flattens one subject's authorization paths that cover the
// resource/operation pair at the given instant: role-derived paths join an
// active binding, the inherited role's active permission grant and an active
// scope on that same role, while direct permission grants stand on their own.
// Overlapping interval versions of one identity collapse into a single path,
// and the result is ordered by the published field sequence.
func subjectGrantPaths(bindings []bindingRow, scopes []scopeRow, rolePerm []rolePermRow,
	model roleModel, resource, operation, at string) []SubjectPath {

	boundRoles := map[string]bool{}
	for _, row := range bindings {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) {
			boundRoles[row.roleID] = true
		}
	}
	reachableCache := map[string]map[string]bool{}
	reachableFrom := func(role string) map[string]bool {
		reachable, ok := reachableCache[role]
		if !ok {
			reachable = reachableRoles(map[string]bool{role: true}, model.roleParents)
			reachableCache[role] = reachable
		}
		return reachable
	}
	activePairs := map[[2]string]bool{}
	for _, row := range rolePerm {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) && model.permOperations[row.permissionID][operation] {
			activePairs[[2]string{row.roleID, row.permissionID}] = true
		}
	}

	paths := []SubjectPath{}
	seen := map[string]bool{}
	add := func(source, boundRole, role, permission, scope string) {
		key := strings.Join([]string{source, boundRole, role, permission, scope}, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		paths = append(paths, SubjectPath{
			Source:     source,
			BoundRole:  nullable(boundRole),
			Role:       nullable(role),
			Permission: permission,
			Scope:      scope,
		})
	}

	for _, row := range scopes {
		if !rowActive(row.effectiveFrom, row.effectiveTo, at) || !row.scope.matches(resource) {
			continue
		}
		if row.permissionID != "" {
			if model.permOperations[row.permissionID][operation] {
				add(SourceDirectPermission, "", "", row.permissionID, row.scope.text)
			}
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

	sort.SliceStable(paths, func(i, j int) bool { return subjectPathLess(paths[i], paths[j]) })
	return paths
}

// subjectPathLess orders paths by source, boundRole, role, permission and
// scope; absent role fields sort as empty text.
func subjectPathLess(a, b SubjectPath) bool {
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
	return a.Scope < b.Scope
}
