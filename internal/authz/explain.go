package authz

import "time"

// ExplainView is the service result of the authorize explanation: the
// decision at one moment together with every authorization path that fully
// covers the resource and operation at that same moment.
type ExplainView struct {
	EffectiveAt string
	Decision    *Decision
	Paths       []SubjectPath
}

// Explain evaluates the triple exactly like Decide and additionally lists
// every authorization path effective at the decision moment, reusing the
// resource reverse lookup's path shape, deduplication and ordering. The
// query is strictly read-only. A malformed effectiveAt is the one failure
// that outranks the triple checks.
func (s *Service) Explain(in DecisionInput) (*ExplainView, *Failure) {
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
	return &ExplainView{
		EffectiveAt: atText,
		Decision:    evaluate(snap, in.Resource, in.Operation, at),
		Paths: subjectGrantPaths(snap.bindings, snap.scopes, snap.rolePerm,
			snap.roleModel, in.Resource, in.Operation, atText),
	}, nil
}
