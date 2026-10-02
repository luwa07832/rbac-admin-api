package authz

import (
	"sort"
	"strconv"
	"time"
)

// Denial reasons returned when granted is false.
const (
	ReasonNoRoleBinding       = "NO_ROLE_BINDING"
	ReasonNoPermissionBinding = "NO_PERMISSION_BINDING"
	ReasonOutOfScope          = "OUT_OF_SCOPE"
	ReasonNotEffective        = "NOT_EFFECTIVE"
)

// DecisionInput is the public authorize payload.
type DecisionInput struct {
	Subject     string `json:"subject"`
	Resource    string `json:"resource"`
	Operation   string `json:"operation"`
	EffectiveAt string `json:"effectiveAt,omitempty"`
}

// BatchDecisionInput is the payload for one batch authorization request.
// Every query shares EffectiveAt and is evaluated independently in order.
type BatchDecisionInput struct {
	EffectiveAt string
	Queries     []BatchDecisionQuery
}

// BatchDecisionQuery identifies one subject/resource/operation triple.
type BatchDecisionQuery struct {
	Subject   string
	Resource  string
	Operation string
}

// BatchDecision pairs one input query with its authorization decision.
type BatchDecision struct {
	Query    BatchDecisionQuery
	Decision *Decision
}

// Match identifies the role-derived or direct authorization that explains a
// granted decision. Role is empty for direct permission grants.
type Match struct {
	Role       string
	Permission string
	Scope      string
}

// Decision is the service-level conclusion.
type Decision struct {
	Granted bool   `json:"-"`
	Reason  string `json:"-"`
	Match   *Match `json:"-"`
}

// Decide evaluates the triple at effectiveAt, defaulting to the current time.
func (s *Service) Decide(in DecisionInput) (*Decision, *Failure) {
	if fail := requireIdentifiers(in.Subject, in.Resource, in.Operation); fail != nil {
		return nil, fail
	}
	if fail := s.checkTriple(in.Subject, in.Resource, in.Operation); fail != nil {
		return nil, fail
	}
	at := time.Now().UTC()
	if in.EffectiveAt != "" {
		parsed, fail := ParseTime(in.EffectiveAt)
		if fail != nil {
			return nil, fail
		}
		at = parsed
	}

	snap, err := s.loadSnapshot(in.Subject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not evaluate authorization")
	}
	return evaluate(snap, in.Resource, in.Operation, at), nil
}

// DecideBatch validates the complete batch before evaluating any query. The
// shared effective moment is parsed once, then each query is checked and
// evaluated in request order; duplicate queries are preserved.
func (s *Service) DecideBatch(in BatchDecisionInput) ([]BatchDecision, *Failure) {
	at := time.Now().UTC()
	if in.EffectiveAt != "" {
		parsed, fail := ParseTime(in.EffectiveAt)
		if fail != nil {
			return nil, fail
		}
		at = parsed
	}
	if len(in.Queries) == 0 || len(in.Queries) > 100 {
		return nil, invalidRequest("queries", "queries must contain between 1 and 100 items")
	}

	snapshots := map[string]*snapshot{}
	decisions := make([]BatchDecision, 0, len(in.Queries))
	for index, query := range in.Queries {
		prefix := batchFieldPrefix(index)
		if fail := requirePrefixedIdentifiers(query.Subject, query.Resource, query.Operation, prefix); fail != nil {
			return nil, fail
		}
		if fail := s.checkTripleWithFieldPrefix(query.Subject, query.Resource, query.Operation, prefix); fail != nil {
			return nil, fail
		}

		snap, ok := snapshots[query.Subject]
		if !ok {
			loaded, err := s.loadSnapshot(query.Subject)
			if err != nil {
				return nil, failure(TypeInvalidRequest, "", "could not evaluate authorization")
			}
			snap = loaded
			snapshots[query.Subject] = snap
		}
		decisions = append(decisions, BatchDecision{
			Query:    query,
			Decision: evaluate(snap, query.Resource, query.Operation, at),
		})
	}
	return decisions, nil
}

func batchFieldPrefix(index int) string {
	return "queries[" + strconv.Itoa(index) + "]."
}

// candidate is one authorization path that structurally covers the triple.
type candidate struct {
	role       string
	permission string
	scope      scopeRef
	from       string
	to         string
}

func candidateLess(a, b candidate) bool {
	if cmp := compareScope(a.scope, b.scope); cmp != 0 {
		return cmp < 0
	}
	if a.permission != b.permission {
		return a.permission < b.permission
	}
	return a.role < b.role
}

// reachableRoles expands statically inherited roles from the entry set.
func reachableRoles(entries map[string]bool, parents map[string][]string) map[string]bool {
	reachable := map[string]bool{}
	queue := make([]string, 0, len(entries))
	for role := range entries {
		reachable[role] = true
		queue = append(queue, role)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, parent := range parents[current] {
			if !reachable[parent] {
				reachable[parent] = true
				queue = append(queue, parent)
			}
		}
	}
	return reachable
}

func activeRoles(snap *snapshot, at string) map[string]bool {
	entries := map[string]bool{}
	for _, row := range snap.bindings {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) {
			entries[row.roleID] = true
		}
	}
	return reachableRoles(entries, snap.roleParents)
}

func rolesEver(snap *snapshot) map[string]bool {
	entries := map[string]bool{}
	for _, row := range snap.bindings {
		entries[row.roleID] = true
	}
	return reachableRoles(entries, snap.roleParents)
}

func rolePermsActive(snap *snapshot, at string) map[[2]string]bool {
	result := map[[2]string]bool{}
	for _, row := range snap.rolePerm {
		if rowActive(row.effectiveFrom, row.effectiveTo, at) {
			result[[2]string{row.roleID, row.permissionID}] = true
		}
	}
	return result
}

func rolePermsEver(snap *snapshot) map[[2]string]bool {
	result := map[[2]string]bool{}
	for _, row := range snap.rolePerm {
		result[[2]string{row.roleID, row.permissionID}] = true
	}
	return result
}

func permissionCovers(snap *snapshot, permissionID, operation string) bool {
	return snap.permOperations[permissionID][operation]
}

// directCandidates returns scope rows that are direct permission grants,
// cover the operation and match the resource pattern. activeOnly filters by
// the given time.
func directCandidates(snap *snapshot, resource, operation, at string, activeOnly bool) []candidate {
	var result []candidate
	for _, row := range snap.scopes {
		if row.permissionID == "" {
			continue
		}
		if !permissionCovers(snap, row.permissionID, operation) || !row.scope.matches(resource) {
			continue
		}
		if activeOnly && !rowActive(row.effectiveFrom, row.effectiveTo, at) {
			continue
		}
		result = append(result, candidate{
			permission: row.permissionID,
			scope:      row.scope,
			from:       row.effectiveFrom,
			to:         row.effectiveTo,
		})
	}
	return result
}

// roleCandidates returns role-derived scope rows reachable through the given
// role set and covering role/permission pairs active at the layer time.
func roleCandidates(snap *snapshot, roles map[string]bool, rolePerms map[[2]string]bool,
	resource, operation, at string, activeOnly bool) []candidate {

	var result []candidate
	for _, row := range snap.scopes {
		if row.permissionID != "" || !roles[row.roleID] || !row.scope.matches(resource) {
			continue
		}
		for pair := range rolePerms {
			if pair[0] != row.roleID || !permissionCovers(snap, pair[1], operation) {
				continue
			}
			if activeOnly && !rowActive(row.effectiveFrom, row.effectiveTo, at) {
				continue
			}
			result = append(result, candidate{
				role:       row.roleID,
				permission: pair[1],
				scope:      row.scope,
				from:       row.effectiveFrom,
				to:         row.effectiveTo,
			})
		}
	}
	return result
}

// evaluate applies the published precedence:
//
//  1. a chain active now (binding, permission, scope interval all contain t)
//     with a scope pattern covering the resource grants;
//  2. otherwise the first layer that structurally existed at some point but is
//     not active now yields NOT_EFFECTIVE;
//  3. a layer that never existed yields its structural reason, with direct
//     permission grants bypassing the role layers.
func evaluate(snap *snapshot, resource, operation string, at time.Time) *Decision {
	atText := FormatTime(at)

	rolesNow := activeRoles(snap, atText)
	rolesPast := rolesEver(snap)
	rolePermsNow := rolePermsActive(snap, atText)
	rolePermsAll := rolePermsEver(snap)

	directNow := directCandidates(snap, resource, operation, atText, true)
	directEver := directCandidates(snap, resource, operation, atText, false)
	roleNowCandidates := roleCandidates(snap, rolesNow, rolePermsNow, resource, operation, atText, true)

	if len(directNow) > 0 {
		return best(directNow)
	}
	if len(roleNowCandidates) > 0 {
		return best(roleNowCandidates)
	}

	// Layer 1 (role-derived path only).
	if len(rolesNow) == 0 && len(rolesPast) > 0 {
		return denied(ReasonNotEffective)
	}

	// Layer 2. A role-derived permission covering the operation is a pair
	// active at the layer time; direct grants live entirely on this layer.
	roleCoversNow := hasCoveringPair(snap, rolesNow, rolePermsNow, operation)
	roleCoversEver := hasCoveringPair(snap, rolesPast, rolePermsAll, operation)

	if !roleCoversNow && (len(directEver) > 0 || roleCoversEver) {
		return denied(ReasonNotEffective)
	}

	// Layer 3. Consider scope rows for paths whose first two layers are
	// active now; an interval that exists but is not active now beats the
	// pattern-mismatch outcome.
	scopeRowsForActivePaths := roleCandidates(snap, rolesNow, rolePermsNow, resource, operation, atText, false)
	if len(directEver) > 0 {
		scopeRowsForActivePaths = append(scopeRowsForActivePaths, directEver...)
	}
	if len(scopeRowsForActivePaths) > 0 {
		return denied(ReasonNotEffective)
	}

	// Structural denials at the first missing layer.
	if len(rolesNow) == 0 {
		return denied(ReasonNoRoleBinding)
	}
	if !roleCoversNow {
		return denied(ReasonNoPermissionBinding)
	}
	return denied(ReasonOutOfScope)
}

func hasCoveringPair(snap *snapshot, roles map[string]bool, rolePerms map[[2]string]bool, operation string) bool {
	for pair := range rolePerms {
		if roles[pair[0]] && permissionCovers(snap, pair[1], operation) {
			return true
		}
	}
	return false
}

func best(candidates []candidate) *Decision {
	sort.SliceStable(candidates, func(i, j int) bool { return candidateLess(candidates[i], candidates[j]) })
	chosen := candidates[0]
	return &Decision{
		Granted: true,
		Match: &Match{
			Role:       chosen.role,
			Permission: chosen.permission,
			Scope:      chosen.scope.text,
		},
	}
}

func denied(reason string) *Decision {
	return &Decision{Granted: false, Reason: reason}
}
