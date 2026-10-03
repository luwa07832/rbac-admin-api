package authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// MaxBatchQueries is the inclusive upper bound on one batch authorize call.
const MaxBatchQueries = 100

// BatchInput is the payload for POST /authorize/batch. EffectiveAtText is the
// raw optional RFC3339 timestamp shared by every query; Queries carries each
// query as a generic JSON value so the service can validate item shape itself.
type BatchInput struct {
	EffectiveAtText *string
	Queries         []json.RawMessage
}

// BatchResultItem is the public echo of one query plus the decision for it.
type BatchResultItem struct {
	Subject   string    `json:"subject"`
	Resource  string    `json:"resource"`
	Operation string    `json:"operation"`
	Decision  *Decision `json:"decision"`
}

// BatchExplainItem is the public echo of one query together with its
// decision and every authorization path effective at the shared moment.
type BatchExplainItem struct {
	Subject   string        `json:"subject"`
	Resource  string        `json:"resource"`
	Operation string        `json:"operation"`
	Decision  *Decision     `json:"decision"`
	Paths     []SubjectPath `json:"paths"`
}

// BatchExplainView is the service result of POST /authorize/batch/explain:
// the canonical shared UTC moment and one decision-plus-paths item per input
// query, kept in strict input order.
type BatchExplainView struct {
	EffectiveAt  string
	Explanations []BatchExplainItem
}

// prepareBatch resolves the shared effectiveAt (defaulting to now) and
// validates every query by index before any evaluation: shape, then
// identifier grammar, then catalog existence in subject/resource/operation
// order. The parsed time outranks every per-query check. It returns the
// validated inputs alongside each subject's snapshot loaded once, so the
// decide and explain entries share identical atomic validation.
func (s *Service) prepareBatch(in BatchInput) (time.Time, []DecisionInput, map[string]*snapshot, *Failure) {
	at := time.Now().UTC()
	if in.EffectiveAtText != nil {
		parsed, fail := ParseTime(*in.EffectiveAtText)
		if fail != nil {
			return time.Time{}, nil, nil, fail
		}
		at = parsed
	}

	validated := make([]DecisionInput, len(in.Queries))
	for index, raw := range in.Queries {
		input, fail := validateBatchQuery(raw, index)
		if fail != nil {
			return time.Time{}, nil, nil, fail
		}
		if fail := s.checkTriple(input.Subject, input.Resource, input.Operation); fail != nil {
			fail.Field = fmt.Sprintf("queries[%d].%s", index, fail.Field)
			return time.Time{}, nil, nil, fail
		}
		validated[index] = input
	}

	// Each subject's snapshot is loaded once; identical triples are evaluated
	// repeatedly so duplicates keep producing their own result.
	snapshots := map[string]*snapshot{}
	for _, input := range validated {
		if _, ok := snapshots[input.Subject]; ok {
			continue
		}
		loaded, err := s.loadSnapshot(input.Subject)
		if err != nil {
			return time.Time{}, nil, nil, failure(TypeInvalidRequest, "", "could not evaluate authorization")
		}
		snapshots[input.Subject] = loaded
	}
	return at, validated, snapshots, nil
}

// BatchDecide validates the whole batch against one shared moment and then
// evaluates every query in input order. Structure validation has already
// rejected a missing, empty, non-array or oversized queries array at the
// entry. Duplicate triples stay separate and no partial result is ever
// returned.
func (s *Service) BatchDecide(in BatchInput) ([]BatchResultItem, *Failure) {
	at, validated, snapshots, fail := s.prepareBatch(in)
	if fail != nil {
		return nil, fail
	}

	results := make([]BatchResultItem, len(validated))
	for index, input := range validated {
		results[index] = BatchResultItem{
			Subject:   input.Subject,
			Resource:  input.Resource,
			Operation: input.Operation,
			Decision:  evaluate(snapshots[input.Subject], input.Resource, input.Operation, at),
		}
	}
	return results, nil
}

// BatchExplain validates the whole batch exactly like BatchDecide and then
// evaluates each query like Explain: the decision at the shared moment plus
// every effective authorization path with the same deduplication and stable
// ordering. The query is strictly read-only; duplicate triples keep their
// own explanation.
func (s *Service) BatchExplain(in BatchInput) (*BatchExplainView, *Failure) {
	at, validated, snapshots, fail := s.prepareBatch(in)
	if fail != nil {
		return nil, fail
	}

	atText := FormatTime(at)
	view := &BatchExplainView{
		EffectiveAt:  atText,
		Explanations: make([]BatchExplainItem, len(validated)),
	}
	for index, input := range validated {
		snap := snapshots[input.Subject]
		view.Explanations[index] = BatchExplainItem{
			Subject:   input.Subject,
			Resource:  input.Resource,
			Operation: input.Operation,
			Decision:  evaluate(snap, input.Resource, input.Operation, at),
			Paths: subjectGrantPaths(snap.bindings, snap.scopes, snap.rolePerm,
				snap.roleModel, input.Resource, input.Operation, atText),
		}
	}
	return view, nil
}

// validateBatchQuery checks one element of the queries array. It must be a
// JSON object containing exactly the subject, resource and operation string
// fields; grammar is checked before catalog existence, each in the published
// subject/resource/operation order.
func validateBatchQuery(raw json.RawMessage, index int) (DecisionInput, *Failure) {
	field := func(name string) string {
		return fmt.Sprintf("queries[%d].%s", index, name)
	}
	baseField := fmt.Sprintf("queries[%d]", index)

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return DecisionInput{}, invalidRequest(baseField, "queries entry must be a JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return DecisionInput{}, invalidRequest(baseField, "queries entry must be a JSON object")
	}

	names := make([]string, 0, len(fields))
	for name := range fields {
		if name != "subject" && name != "resource" && name != "operation" {
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		sort.Strings(names)
		return DecisionInput{}, invalidRequest(field(names[0]), "field is not allowed on a batch query")
	}

	var input DecisionInput
	pairs := []struct {
		name string
		dest *string
	}{
		{"subject", &input.Subject},
		{"resource", &input.Resource},
		{"operation", &input.Operation},
	}
	for _, pair := range pairs {
		rawValue, present := fields[pair.name]
		if !present {
			return DecisionInput{}, invalidRequest(field(pair.name), "field "+pair.name+" is required")
		}
		var text string
		if err := json.Unmarshal(rawValue, &text); err != nil {
			return DecisionInput{}, invalidRequest(field(pair.name), "field "+pair.name+" must be a string")
		}
		*pair.dest = text
	}

	for _, pair := range pairs {
		if !validIdentifier(*pair.dest) {
			return DecisionInput{}, invalidRequest(field(pair.name), "field "+pair.name+" is not a parseable identifier")
		}
	}
	return input, nil
}
