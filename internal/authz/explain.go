package authz

import "time"

// ExplainInput is the read-only authorization explanation payload. It carries
// the same subject/resource/operation triple as Decide and an optional
// evaluation moment.
type ExplainInput struct {
	Subject     string
	Resource    string
	Operation   string
	EffectiveAt string
}

// ExplainResult pairs the decision identical to Decide with every path fully
// covering the resource/operation pair at the evaluation moment.
type ExplainResult struct {
	At       string
	Decision *Decision
	Paths    []SubjectPath
}

// Explain evaluates the triple at effectiveAt (defaulting to now) and returns
// both the published decision and every effective authorization path at that
// moment. The query is strictly read-only and an empty path set is a normal
// outcome. Time validation outranks the triple checks, matching the other
// read entries; the decision runs through the same evaluator as Decide, so a
// concurrent POST /authorize at the same moment yields the same result.
func (s *Service) Explain(in ExplainInput) (*ExplainResult, *Failure) {
	at := time.Now().UTC()
	if in.EffectiveAt != "" {
		parsed, fail := ParseTime(in.EffectiveAt)
		if fail != nil {
			return nil, fail
		}
		at = parsed
	}
	if fail := requireIdentifiers(in.Subject, in.Resource, in.Operation); fail != nil {
		return nil, fail
	}
	if fail := s.checkTriple(in.Subject, in.Resource, in.Operation); fail != nil {
		return nil, fail
	}

	snap, err := s.loadSnapshot(in.Subject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate authorization")
	}
	atText := FormatTime(at)
	decision := evaluate(snap, in.Resource, in.Operation, at)
	paths := subjectGrantPaths(snap.bindings, snap.scopes, snap.rolePerm, snap.roleModel,
		in.Resource, in.Operation, atText)
	return &ExplainResult{At: atText, Decision: decision, Paths: paths}, nil
}
