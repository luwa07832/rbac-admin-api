package authz

import (
	"sort"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// ResourceSubjectsDiffInput compares the subjects granted one
// resource/operation pair at two mandatory moments.
type ResourceSubjectsDiffInput struct {
	Resource  string
	Operation string
	From      string
	To        string
}

// ResourceSubjectDiffItem groups one subject's symmetric path difference.
// Every array renders as an array even when empty.
type ResourceSubjectDiffItem struct {
	Subject   string        `json:"subject"`
	Added     []SubjectPath `json:"added"`
	Removed   []SubjectPath `json:"removed"`
	Unchanged []SubjectPath `json:"unchanged"`
}

// ResourceSubjectsDiffView is the public shape of
// GET /resources/{resource}/subjects/diff. Subjects with a path at either
// moment are included; equal moments put every path in unchanged.
type ResourceSubjectsDiffView struct {
	From      string                    `json:"from"`
	To        string                    `json:"to"`
	Resource  string                    `json:"resource"`
	Operation string                    `json:"operation"`
	Subjects  []ResourceSubjectDiffItem `json:"subjects"`
}

// ResourceSubjectsDiff lists, per subject, which grant paths covering the
// resource/operation pair were added, removed or kept between two moments.
// Both moments are mandatory and the query is read-only. Timing validation
// outranks resource and operation validation, with from reported before to;
// equal moments are a normal request.
func (s *Service) ResourceSubjectsDiff(in ResourceSubjectsDiffInput) (*ResourceSubjectsDiffView, *Failure) {
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
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects diff")
	}
	model, err := s.loadRoleModel()
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects diff")
	}
	subjectIDs, err := s.store.ListCatalog(store.CatalogSubject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects diff")
	}

	view := &ResourceSubjectsDiffView{
		From:      FormatTime(fromTime),
		To:        FormatTime(toTime),
		Resource:  in.Resource,
		Operation: in.Operation,
		Subjects:  []ResourceSubjectDiffItem{},
	}
	fromText := FormatTime(fromTime)
	toText := FormatTime(toTime)
	for _, subjectID := range subjectIDs {
		bindings, scopes, err := s.loadSubjectRows(subjectID)
		if err != nil {
			return nil, failure(TypeInvalidRequest, "", "could not evaluate resource subjects diff")
		}
		fromPaths := subjectGrantPaths(bindings, scopes, rolePermRows, model, in.Resource, in.Operation, fromText)
		toPaths := subjectGrantPaths(bindings, scopes, rolePermRows, model, in.Resource, in.Operation, toText)
		item := diffSubjectPaths(subjectID, fromPaths, toPaths)
		if item == nil {
			continue
		}
		view.Subjects = append(view.Subjects, *item)
	}
	sort.SliceStable(view.Subjects, func(i, j int) bool {
		return view.Subjects[i].Subject < view.Subjects[j].Subject
	})
	return view, nil
}

// diffSubjectPaths classifies one subject's grant paths against the two
// moments. Both inputs are already deduplicated and ordered by
// subjectGrantPaths, so membership filtering keeps the published ordering.
// It returns nil when the subject has no path at either moment.
func diffSubjectPaths(subject string, fromPaths, toPaths []SubjectPath) *ResourceSubjectDiffItem {
	if len(fromPaths) == 0 && len(toPaths) == 0 {
		return nil
	}
	fromKeys := map[string]bool{}
	for _, path := range fromPaths {
		fromKeys[pathKey(path)] = true
	}
	toKeys := map[string]bool{}
	for _, path := range toPaths {
		toKeys[pathKey(path)] = true
	}
	item := &ResourceSubjectDiffItem{
		Subject:   subject,
		Added:     []SubjectPath{},
		Removed:   []SubjectPath{},
		Unchanged: []SubjectPath{},
	}
	for _, path := range toPaths {
		if fromKeys[pathKey(path)] {
			item.Unchanged = append(item.Unchanged, path)
		} else {
			item.Added = append(item.Added, path)
		}
	}
	for _, path := range fromPaths {
		if !toKeys[pathKey(path)] {
			item.Removed = append(item.Removed, path)
		}
	}
	return item
}
