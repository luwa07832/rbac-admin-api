package authz

import (
	"fmt"
	"time"
)

// BatchExplainResultItem is the public echo of one batch explain query plus
// the decision for it and every authorization path effective at the shared
// moment.
type BatchExplainResultItem struct {
	Subject   string        `json:"subject"`
	Resource  string        `json:"resource"`
	Operation string        `json:"operation"`
	Decision  *Decision     `json:"decision"`
	Paths     []SubjectPath `json:"paths"`
}

// BatchExplainView is the service result of POST /authorize/batch/explain:
// the canonical shared moment and one explanation per query, in input order.
type BatchExplainView struct {
	EffectiveAt  string
	Explanations []BatchExplainResultItem
}

// BatchExplain validates the whole batch against one shared moment and then
// explains every query in input order, mirroring BatchDecide for structure
// validation and Explain for path collection. Duplicate triples stay
// separate and no partial result is ever returned. The query is strictly
// read-only and never writes history.
func (s *Service) BatchExplain(in BatchInput) (*BatchExplainView, *Failure) {
	at := time.Now().UTC()
	if in.EffectiveAtText != nil {
		parsed, fail := ParseTime(*in.EffectiveAtText)
		if fail != nil {
			return nil, fail
		}
		at = parsed
	}

	validated := make([]DecisionInput, len(in.Queries))
	for index, raw := range in.Queries {
		input, fail := validateBatchQuery(raw, index)
		if fail != nil {
			return nil, fail
		}
		if fail := s.checkTriple(input.Subject, input.Resource, input.Operation); fail != nil {
			fail.Field = fmt.Sprintf("queries[%d].%s", index, fail.Field)
			return nil, fail
		}
		validated[index] = input
	}

	// Each subject's snapshot is loaded once; identical triples are explained
	// repeatedly so duplicates keep producing their own result.
	snapshots := map[string]*snapshot{}
	atText := FormatTime(at)
	explanations := make([]BatchExplainResultItem, len(validated))
	for index, input := range validated {
		snap, ok := snapshots[input.Subject]
		if !ok {
			loaded, err := s.loadSnapshot(input.Subject)
			if err != nil {
				return nil, failure(TypeInvalidRequest, "", "could not evaluate authorization")
			}
			snap = loaded
			snapshots[input.Subject] = snap
		}
		explanations[index] = BatchExplainResultItem{
			Subject:   input.Subject,
			Resource:  input.Resource,
			Operation: input.Operation,
			Decision:  evaluate(snap, input.Resource, input.Operation, at),
			Paths: subjectGrantPaths(snap.bindings, snap.scopes, snap.rolePerm,
				snap.roleModel, input.Resource, input.Operation, atText),
		}
	}
	return &BatchExplainView{EffectiveAt: atText, Explanations: explanations}, nil
}
