package authz

import "sort"

// HistoryRange optionally narrows change events by occurredAt boundaries.
type HistoryRange struct {
	HasFrom bool
	From    int64
	HasTo   bool
	To      int64
}

// chain is one structurally complete authorization path restricted to one
// overlapping validity interval of the layers that form it.
type chain struct {
	role        string
	via         string
	perm        string
	scope       Scope
	from        int64
	to          int64
	hasTo       bool
	openSeq     int64
	closeSeq    int64
	closeReason string
}

// buildChains enumerates every window on which one copy could be granted:
// permission covers operation, scope contains resource, and (for role chains)
// the binding interval and role-permission interval overlap.
func buildChains(input Input, data Data) []chain {
	permCoversOp := indexPermissionOperations(data.PermissionOperations, input.Operation)
	result := make([]chain, 0)

	for _, grant := range data.GrantVersions {
		if !permCoversOp[grant.Permission] || !ScopeCovers(grant.Scope, input.Resource) {
			continue
		}
		result = append(result, chain{
			via: "direct", perm: grant.Permission, scope: grant.Scope,
			from: grant.From, to: grant.To, hasTo: grant.HasTo,
			openSeq: grant.Seq, closeSeq: grant.Seq, closeReason: grant.CloseReason,
		})
	}

	reachable := reachableRoles(data.RoleParents)
	rolePerms := indexRolePermissionVersions(data.RolePermissionVersions)
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
				if !overlaps {
					continue
				}
				// seq/reason belong to whichever layer opens and closes the
				// overlapping chain window.
				openSeq := binding.Seq
				if authorization.From > binding.From {
					openSeq = authorization.Seq
				}
				closeSeq := binding.Seq
				closeReason := binding.CloseReason
				if hasTo {
					if endsAt(binding.HasTo, binding.To, authorization.HasTo, authorization.To) {
						closeSeq, closeReason = binding.Seq, binding.CloseReason
					} else {
						closeSeq, closeReason = authorization.Seq, CloseRevoke
					}
				}
				result = append(result, chain{
					role: binding.Role, via: "role", perm: authorization.Permission,
					scope: binding.Scope, from: from, to: to, hasTo: hasTo,
					openSeq: openSeq, closeSeq: closeSeq, closeReason: closeReason,
				})
			}
		}
	}
	return result
}

// updatePair describes one scope replacement on a binding: the old window
// closes with reason "update" and the new window opens at the same instant.
type updatePair struct {
	role  string
	scope Scope
	to    int64
	hasTo bool
	seq   int64
}

// buildUpdatePairs indexes scope replacements for the queried subject. The
// index key is the close instant; a chain closing there with reason "update"
// belongs to the pair with the same role.
func buildUpdatePairs(data Data) map[int64]map[string]updatePair {
	// Pairs are recovered from the interval rows: the row that opens at the
	// same instant another interval of the same role closes with reason
	// "update" is the replacement carrying the new scope.
	pairs := make(map[int64]map[string]updatePair)
	byRole := make(map[string][]RoleVersion)
	for _, row := range data.RoleVersions {
		byRole[row.Role] = append(byRole[row.Role], row)
	}
	for role, rows := range byRole {
		for _, old := range rows {
			if old.CloseReason != CloseUpdate || !old.HasTo {
				continue
			}
			for _, next := range rows {
				if next.From == old.To && next.Seq != old.Seq {
					if pairs[old.To] == nil {
						pairs[old.To] = make(map[string]updatePair)
					}
					pairs[old.To][role] = updatePair{
						role: role, scope: next.Scope,
						to: next.To, hasTo: next.HasTo, seq: next.Seq,
					}
					break
				}
			}
		}
	}
	return pairs
}

func winnerAt(chains []chain, at int64) *chain {
	eligible := make([]chain, 0)
	for _, item := range chains {
		if item.from <= at && (!item.hasTo || item.to > at) {
			eligible = append(eligible, item)
		}
	}
	if len(eligible) == 0 {
		return nil
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		return moreSpecific(toPath(eligible[i]), toPath(eligible[j]))
	})
	winner := eligible[0]
	return &winner
}

func toPath(c chain) path {
	return path{role: c.role, via: c.via, perm: c.perm, scope: c.scope}
}

func sameIdentity(a, b *chain) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.role == b.role && a.via == b.via && a.perm == b.perm && a.scope == b.scope
}

// Timeline rebuilds, for one subject/resource/operation triple, the sequence of
// authorization changes by sweeping the half-open validity intervals stored
// on the three layers. Events are returned oldest first; changes sharing one
// effective instant keep the stable order of their write sequence.
func Timeline(input Input, data Data, historyRange HistoryRange) []Event {
	chains := buildChains(input, data)
	pairs := buildUpdatePairs(data)

	boundaries := make(map[int64]int64)
	note := func(at, seq int64) {
		if existing, ok := boundaries[at]; !ok || seq < existing {
			boundaries[at] = seq
		}
	}
	for _, item := range chains {
		note(item.from, item.openSeq)
		if item.hasTo {
			note(item.to, item.closeSeq)
		}
	}

	ordered := make([]int64, 0, len(boundaries))
	for at := range boundaries {
		ordered = append(ordered, at)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i] != ordered[j] {
			return ordered[i] < ordered[j]
		}
		return boundaries[ordered[i]] < boundaries[ordered[j]]
	})

	events := make([]Event, 0)
	var previous *chain
	for _, at := range ordered {
		current := winnerAt(chains, at)

		// Scope replacement (UPDATE): one role binding closes with reason
		// "update" while the same role reopens with a new scope at this instant.
		// When the affected triple keeps being granted through that role the
		// change is one UPDATE; when access flips it becomes REVOKE or GRANT,
		// carrying the scope on the side that matters for the triple.
		updateRole := ""
		if previous != nil && previous.via == "role" {
			if _, ok := pairs[at][previous.role]; ok {
				updateRole = previous.role
			}
		}
		if updateRole == "" && current != nil && current.via == "role" {
			if _, ok := pairs[at][current.role]; ok {
				updateRole = current.role
			}
		}
		continues := updateRole != "" && previous != nil && current != nil &&
			previous.role == updateRole && current.role == updateRole &&
			previous.perm == current.perm
		if updateRole != "" && continues {
			pair := pairs[at][updateRole]
			events = append(events, updateEvent(at, pair, current.perm))
			previous = current
			continue
		}

		switch {
		case previous == nil && current != nil:
			events = append(events, grantEvent(EventGrant, at, current))
		case previous != nil && current == nil:
			events = append(events, pointEvent(EventRevoke, at, previous, false))
		case previous != nil && current != nil && !sameIdentity(previous, current):
			events = append(events, pointEvent(EventRevoke, at, previous, false))
			events = append(events, grantEvent(EventGrant, at, current))
		}
		previous = current
	}

	filtered := make([]Event, 0, len(events))
	for _, event := range events {
		if historyRange.HasFrom && event.OccurredAt < historyRange.From {
			continue
		}
		if historyRange.HasTo && event.OccurredAt > historyRange.To {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func updateEvent(at int64, pair updatePair, permission string) Event {
	event := Event{
		Event:         EventUpdate,
		OccurredAt:    at,
		EffectiveFrom: at,
		EffectiveTo:   nil,
		Role:          pair.role,
		Permission:    permission,
		Scope:         pair.scope,
		Granted:       true,
		Seq:           pair.seq,
	}
	if pair.hasTo {
		end := pair.to
		event.EffectiveTo = &end
	}
	return event
}

// grantEvent describes a window that starts at occurredAt and ends at the
// chain window end (open when the authorization is still in force).
func grantEvent(kind string, at int64, item *chain) Event {
	event := Event{
		Event:         kind,
		OccurredAt:    at,
		EffectiveFrom: at,
		EffectiveTo:   nil,
		Role:          item.role,
		Permission:    item.perm,
		Scope:         item.scope,
		Granted:       true,
		Seq:           item.openSeq,
	}
	if item.hasTo {
		end := item.to
		event.EffectiveTo = &end
	}
	return event
}

// pointEvent reports an instant such as a revocation; the effective window is
// the single instant the change occurred on.
func pointEvent(kind string, at int64, item *chain, granted bool) Event {
	end := at
	return Event{
		Event:         kind,
		OccurredAt:    at,
		EffectiveFrom: at,
		EffectiveTo:   &end,
		Role:          item.role,
		Permission:    item.perm,
		Scope:         item.scope,
		Granted:       granted,
		Seq:           item.closeSeq,
	}
}

// endsAt reports whether the first interval ends no later than the second.
func endsAt(aHas bool, aTo int64, bHas bool, bTo int64) bool {
	if !aHas {
		return false
	}
	if !bHas {
		return true
	}
	return aTo <= bTo
}
