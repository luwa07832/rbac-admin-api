package authz

import "github.com/luwa07832/rbac-admin-api/internal/store"

// AccessDiffInput is the read-only comparison of one subject's effective
// authorization paths between two required moments.
type AccessDiffInput struct {
	Subject string
	From    string
	To      string
}

// AccessDiffView is the public shape of
// GET /subjects/{subject}/access/diff. Every collection renders as an array
// even when empty.
type AccessDiffView struct {
	From      string       `json:"from"`
	To        string       `json:"to"`
	Added     []AccessItem `json:"added"`
	Removed   []AccessItem `json:"removed"`
	Unchanged []AccessItem `json:"unchanged"`
}

// AccessDiff lists which of the subject's effective authorization paths were
// added, removed or left unchanged between two moments. Each moment is
// evaluated with the same half-open interval semantics as Access; equal
// moments simply classify every path as unchanged. The query is read-only
// and writes no change history.
//
// Parameter validation follows the published precedence: the from/to
// presence checks, then RFC3339 parsing (from first), then the range check,
// and only afterwards the subject grammar and existence.
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
	fromText := FormatTime(fromTime)
	toText := FormatTime(toTime)
	fromItems := listAccess(snap, fromText)
	toItems := listAccess(snap, toText)

	fromByKey := map[string]AccessItem{}
	for _, item := range fromItems {
		fromByKey[accessKey(item)] = item
	}
	toByKey := map[string]AccessItem{}
	for _, item := range toItems {
		toByKey[accessKey(item)] = item
	}

	view := &AccessDiffView{
		From:      fromText,
		To:        toText,
		Added:     []AccessItem{},
		Removed:   []AccessItem{},
		Unchanged: []AccessItem{},
	}
	for _, item := range toItems {
		if _, ok := fromByKey[accessKey(item)]; !ok {
			view.Added = append(view.Added, item)
		} else {
			view.Unchanged = append(view.Unchanged, item)
		}
	}
	for _, item := range fromItems {
		if _, ok := toByKey[accessKey(item)]; !ok {
			view.Removed = append(view.Removed, item)
		}
	}

	return view, nil
}
