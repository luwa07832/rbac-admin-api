package authz

import (
	"sort"
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// ResourceSubjectsInput is the read-only reverse query: every subject
// authorized on one resource/operation pair at one moment.
type ResourceSubjectsInput struct {
	Resource    string
	Operation   string
	EffectiveAt string
}

// ResourceSubjectPath is one effective authorization path of one subject. It
// mirrors AccessItem without the operation set, since the queried operation
// already constrains the path.
type ResourceSubjectPath struct {
	Source     string  `json:"source"`
	BoundRole  *string `json:"boundRole"`
	Role       *string `json:"role"`
	Permission string  `json:"permission"`
	Scope      string  `json:"scope"`
}

// ResourceSubjectEntry groups the deduplicated effective paths of one subject.
type ResourceSubjectEntry struct {
	Subject string                `json:"subject"`
	Paths   []ResourceSubjectPath `json:"paths"`
}

// ResourceSubjectsView is the public shape of GET /resources/{resource}/subjects.
type ResourceSubjectsView struct {
	EffectiveAt string                 `json:"effectiveAt"`
	Resource    string                 `json:"resource"`
	Operation   string                 `json:"operation"`
	Subjects    []ResourceSubjectEntry `json:"subjects"`
}

// ResourceSubjects answers the reverse of Access: which registered subjects
// hold an effective path on the resource/operation pair at effectiveAt
// (defaulting to now). The query is strictly read-only, and a world with no
// effective subject is a normal empty result, never an error. A malformed
// effectiveAt outranks every other validation, followed by resource then
// operation grammar and existence.
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
	if exists, err := s.store.Exists(store.CatalogResource, in.Resource); err != nil || !exists {
		return nil, notFoundOrInternal("resource", err, !exists)
	}
	if in.Operation == "" {
		return nil, invalidRequest("operation", "field operation is required")
	}
	if !validIdentifier(in.Operation) {
		return nil, invalidRequest("operation", "field operation is not a parseable identifier")
	}
	if exists, err := s.store.Exists(store.CatalogOperation, in.Operation); err != nil || !exists {
		return nil, notFoundOrInternal("operation", err, !exists)
	}

	subjectIDs, err := s.store.ListCatalog(store.CatalogSubject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects")
	}
	sort.Strings(subjectIDs)

	model, err := s.loadRoleModel()
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects")
	}
	rolePermRows, err := s.loadRolePermissionRows()
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects")
	}

	atText := FormatTime(at)
	filter := pathFilter{resource: in.Resource, operation: in.Operation}
	entries := []ResourceSubjectEntry{}
	for _, subjectID := range subjectIDs {
		snap, err := s.loadSnapshotData(subjectID, model, rolePermRows)
		if err != nil {
			return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects")
		}
		items := collectPaths(snap, atText, filter)
		if len(items) == 0 {
			continue
		}
		paths := make([]ResourceSubjectPath, 0, len(items))
		for _, item := range items {
			paths = append(paths, ResourceSubjectPath{
				Source:     item.Source,
				BoundRole:  item.BoundRole,
				Role:       item.Role,
				Permission: item.Permission,
				Scope:      item.Scope,
			})
		}
		sort.SliceStable(paths, func(i, j int) bool { return pathLess(paths[i], paths[j]) })
		entries = append(entries, ResourceSubjectEntry{Subject: subjectID, Paths: paths})
	}

	return &ResourceSubjectsView{
		EffectiveAt: atText,
		Resource:    in.Resource,
		Operation:   in.Operation,
		Subjects:    entries,
	}, nil
}

// pathLess orders paths by source, boundRole, role, permission and scope;
// absent role fields sort as empty text.
func pathLess(a, b ResourceSubjectPath) bool {
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
