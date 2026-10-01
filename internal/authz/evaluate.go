package authz

import "sort"

// EvaluateAt answers whether input is granted at instant at.
//
// The stored layers are inspected structurally first (ignoring time and even
// the overlap between two layer windows), in the published order:
//  1. the subject carries no role binding or direct grant at all ->
//     NO_ROLE_BINDING;
//  2. a binding/grant exists but, through any reachable role, no permission
//     point covers the operation -> NO_PERMISSION_BINDING;
//  3. an operation-covering permission exists but every copy lives on a scope
//     that does not contain the resource -> OUT_OF_SCOPE;
//  4. every layer matches structurally, yet no complete copy is in force at
//     the asked instant -> NOT_EFFECTIVE;
//  5. otherwise granted, explained by the most specific effective copy.
func EvaluateAt(input Input, data Data, at int64) Decision {
	if len(data.RoleVersions) == 0 && len(data.GrantVersions) == 0 {
		return Decision{Granted: false, Reason: ReasonNoRoleBinding}
	}

	permCoversOp := indexPermissionOperations(data.PermissionOperations, input.Operation)
	reachable := reachableRoles(data.RoleParents)
	rolePerms := indexRolePermissionVersions(data.RolePermissionVersions)

	// Structural pass: does each layer exist for this triple?
	permissionLayer := false
	scopeLayer := false
	for _, grant := range data.GrantVersions {
		if !permCoversOp[grant.Permission] {
			continue
		}
		permissionLayer = true
		if ScopeCovers(grant.Scope, input.Resource) {
			scopeLayer = true
		}
	}
	for _, binding := range data.RoleVersions {
		roles := reachable[binding.Role]
		if roles == nil {
			roles = []string{binding.Role}
		}
		for _, role := range roles {
			roleHasCovering := false
			for _, authorization := range rolePerms[role] {
				if permCoversOp[authorization.Permission] {
					roleHasCovering = true
					break
				}
			}
			if !roleHasCovering {
				continue
			}
			permissionLayer = true
			if ScopeCovers(binding.Scope, input.Resource) {
				scopeLayer = true
			}
		}
	}

	if !permissionLayer {
		return Decision{Granted: false, Reason: ReasonNoPermissionBinding}
	}
	if !scopeLayer {
		return Decision{Granted: false, Reason: ReasonOutOfScope}
	}

	// Temporal pass: require a complete copy in force at at.
	candidates := make([]path, 0)
	for _, grant := range data.GrantVersions {
		if !permCoversOp[grant.Permission] {
			continue
		}
		if !ScopeCovers(grant.Scope, input.Resource) {
			continue
		}
		if !activeAt(grant.From, grant.HasTo, grant.To, at) {
			continue
		}
		candidates = append(candidates, path{
			via: "direct", perm: grant.Permission, scope: grant.Scope,
		})
	}
	for _, binding := range data.RoleVersions {
		if !ScopeCovers(binding.Scope, input.Resource) {
			continue
		}
		roles := reachable[binding.Role]
		if roles == nil {
			roles = []string{binding.Role}
		}
		seen := map[string]bool{}
		for _, role := range roles {
			if seen[role] {
				continue
			}
			seen[role] = true
			for _, authorization := range rolePerms[role] {
				if !permCoversOp[authorization.Permission] {
					continue
				}
				from, hasTo, to, overlaps := intersect(
					binding.From, binding.HasTo, binding.To,
					authorization.From, authorization.HasTo, authorization.To)
				if !overlaps || !activeAt(from, hasTo, to, at) {
					continue
				}
				candidates = append(candidates, path{
					role: binding.Role, via: "role",
					perm: authorization.Permission, scope: binding.Scope,
				})
			}
		}
	}
	if len(candidates) == 0 {
		return Decision{Granted: false, Reason: ReasonNotEffective}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return moreSpecific(candidates[i], candidates[j])
	})
	winner := candidates[0]
	return Decision{
		Granted: true,
		Match: &Match{
			Role:       winner.role,
			Permission: winner.perm,
			Scope:      winner.scope,
		},
	}
}
