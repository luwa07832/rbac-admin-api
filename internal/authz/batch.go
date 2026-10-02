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

// BatchDecide validates the whole batch against one shared moment and then
// evaluates every query in input order. Structure validation has already
// rejected a missing, empty, non-array or oversized queries array at the
// entry; here the effectiveAt is parsed before the first per-query check,
// and queries are validated by index: shape, then identifier grammar, then
// catalog existence in subject/resource/operation order. Duplicate triples
// stay separate and no partial result is ever returned.
func (s *Service) BatchDecide(in BatchInput) ([]BatchResultItem, *Failure) {
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

	// Each subject's snapshot is loaded once; identical triples are evaluated
	// repeatedly so duplicates keep producing their own decision.
	snapshots := map[string]*snapshot{}
	results := make([]BatchResultItem, len(validated))
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
		results[index] = BatchResultItem{
			Subject:   input.Subject,
			Resource:  input.Resource,
			Operation: input.Operation,
			Decision:  evaluate(snap, input.Resource, input.Operation, at),
		}
	}
	return results, nil
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
