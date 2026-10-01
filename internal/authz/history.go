package authz

import (
	"sort"
	"time"
)

// HistoryInput is the public change-history query.
type HistoryInput struct {
	Subject   string
	Resource  string
	Operation string
	From      string
	To        string
}

// HistoryEvent is one relevant change in public shape. Nullable fields stay
// null when they do not apply to the event's layer.
type HistoryEvent struct {
	Event         string  `json:"event"`
	OccurredAt    string  `json:"occurredAt"`
	EffectiveFrom string  `json:"effectiveFrom"`
	EffectiveTo   *string `json:"effectiveTo"`
	Role          *string `json:"role"`
	Permission    *string `json:"permission"`
	Scope         *string `json:"scope"`
	Granted       bool    `json:"granted"`
	seq           int64   `json:"-"`
}

// History returns the subject's changes relevant to the resource/operation
// triple, filtered to intervals whose effectiveFrom falls in [from,to] and
// ordered by effectiveFrom, occurredAt, then insertion order.
func (s *Service) History(in HistoryInput) ([]HistoryEvent, *Failure) {
	if fail := requireIdentifiers(in.Subject, in.Resource, in.Operation); fail != nil {
		return nil, fail
	}
	if fail := s.checkTriple(in.Subject, in.Resource, in.Operation); fail != nil {
		return nil, fail
	}

	var fromTime, toTime time.Time
	if in.From != "" {
		parsed, fail := ParseTime(in.From)
		if fail != nil {
			fail.Field = "from"
			return nil, fail
		}
		fromTime = parsed
	}
	if in.To != "" {
		parsed, fail := ParseTime(in.To)
		if fail != nil {
			fail.Field = "to"
			return nil, fail
		}
		toTime = parsed
	}
	if in.From != "" && in.To != "" && fromTime.After(toTime) {
		return nil, failure(TypeInvalidRange, "", "the range start must not be later than the range end")
	}

	snap, err := s.loadSnapshot(in.Subject)
	if err != nil {
		return nil, failure(TypeInvalidRequest, "", "could not read change history")
	}

	fromText, toText := "", ""
	if in.From != "" {
		fromText = FormatTime(fromTime)
	}
	if in.To != "" {
		toText = FormatTime(toTime)
	}

	events := []HistoryEvent{}
	for _, row := range snap.bindings {
		if bindingRelevant(snap, row, in.Resource, in.Operation) {
			events = append(events, eventFromBinding(snap, row, in.Resource, in.Operation))
		}
	}
	for _, row := range snap.rolePerm {
		if rolePermRelevant(snap, row, in.Resource, in.Operation) {
			events = append(events, eventFromRolePerm(snap, row, in.Resource, in.Operation))
		}
	}
	for _, row := range snap.scopes {
		if scopeRelevant(snap, row, in.Resource, in.Operation) {
			events = append(events, eventFromScope(snap, row, in.Resource, in.Operation))
		}
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].EffectiveFrom != events[j].EffectiveFrom {
			return events[i].EffectiveFrom < events[j].EffectiveFrom
		}
		if events[i].OccurredAt != events[j].OccurredAt {
			return events[i].OccurredAt < events[j].OccurredAt
		}
		return events[i].seq < events[j].seq
	})

	filtered := events[:0]
	for _, event := range events {
		if fromText != "" && event.EffectiveFrom < fromText {
			continue
		}
		if toText != "" && event.EffectiveFrom > toText {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered, nil
}

// forcedChange overlays one interval row's post-event state onto an as-of
// evaluation.
type forcedChange struct {
	kind string // "binding", "rolePerm", "scope"
	seq  int64
	on   bool
}

// grantedAt reports the post-event decision for the triple as of atText.
func grantedAt(snap *snapshot, resource, operation, atText string, forced *forcedChange) bool {
	bindingEntries := map[string]bool{}
	for _, row := range snap.bindings {
		active := rowActive(row.effectiveFrom, row.effectiveTo, atText)
		if forced != nil && forced.kind == "binding" && row.seq == forced.seq {
			active = forced.on
		}
		if active {
			bindingEntries[row.roleID] = true
		}
	}
	roles := reachableRoles(bindingEntries, snap.roleParents)

	rolePerms := map[[2]string]bool{}
	for _, row := range snap.rolePerm {
		active := rowActive(row.effectiveFrom, row.effectiveTo, atText)
		if forced != nil && forced.kind == "rolePerm" && row.seq == forced.seq {
			active = forced.on
		}
		if active {
			rolePerms[[2]string{row.roleID, row.permissionID}] = true
		}
	}

	for _, row := range snap.scopes {
		active := rowActive(row.effectiveFrom, row.effectiveTo, atText)
		if forced != nil && forced.kind == "scope" && row.seq == forced.seq {
			active = forced.on
		}
		if !active || !row.scope.matches(resource) {
			continue
		}
		if row.permissionID != "" {
			if permissionCovers(snap, row.permissionID, operation) {
				return true
			}
			continue
		}
		if !roles[row.roleID] {
			continue
		}
		for pair := range rolePerms {
			if pair[0] == row.roleID && permissionCovers(snap, pair[1], operation) {
				return true
			}
		}
	}
	return false
}

// postEventOn reports whether the event row is present after its own event:
// GRANT and UPDATE rows are on; a REVOKE row represents removal, so the
// identity is off.
func postEventOn(event string) bool { return event != "REVOKE" }

// bindingRelevant keeps a binding change when, in the post-event world, the
// bound (or released) role reaches a permission covering the operation through
// a scope pattern matching the resource.
func bindingRelevant(snap *snapshot, row bindingRow, resource, operation string) bool {
	rolePerms := map[[2]string]bool{}
	for _, pair := range snap.rolePerm {
		rolePerms[[2]string{pair.roleID, pair.permissionID}] = true
	}
	reachable := reachableRoles(map[string]bool{row.roleID: true}, snap.roleParents)
	for role := range reachable {
		for pair := range rolePerms {
			if pair[0] != role || !permissionCovers(snap, pair[1], operation) {
				continue
			}
			for _, scope := range snap.scopes {
				if scope.roleID == role && scope.scope.matches(resource) {
					return true
				}
			}
		}
	}
	return false
}

// rolePermRelevant keeps a role/permission change when a scope on that role
// matches the resource and the permission covers the operation, provided the
// role is reachable through some binding interval in the post-event world.
func rolePermRelevant(snap *snapshot, row rolePermRow, resource, operation string) bool {
	if !permissionCovers(snap, row.permissionID, operation) {
		return false
	}
	hasScope := false
	for _, scope := range snap.scopes {
		if scope.roleID == row.roleID && scope.scope.matches(resource) {
			hasScope = true
			break
		}
	}
	if !hasScope {
		return false
	}
	for _, binding := range snap.bindings {
		reachable := reachableRoles(map[string]bool{binding.roleID: true}, snap.roleParents)
		if reachable[row.roleID] {
			return true
		}
	}
	return false
}

// scopeRelevant keeps a scope change whose pattern matches the resource and
// whose (role, permission) or direct permission covers the operation, with
// role reachability through some binding interval.
func scopeRelevant(snap *snapshot, row scopeRow, resource, operation string) bool {
	if !row.scope.matches(resource) {
		return false
	}
	if row.permissionID != "" {
		return permissionCovers(snap, row.permissionID, operation)
	}
	covers := false
	for _, pair := range snap.rolePerm {
		if pair.roleID == row.roleID && permissionCovers(snap, pair.permissionID, operation) {
			covers = true
			break
		}
	}
	if !covers {
		return false
	}
	for _, binding := range snap.bindings {
		reachable := reachableRoles(map[string]bool{binding.roleID: true}, snap.roleParents)
		if reachable[row.roleID] {
			return true
		}
	}
	return false
}

func nullable(value string) *string {
	if value == "" {
		return nil
	}
	result := value
	return &result
}

func effectiveToPointer(value string) *string {
	if value == "" {
		return nil
	}
	result := value
	return &result
}

func eventFromBinding(snap *snapshot, row bindingRow, resource, operation string) HistoryEvent {
	granted := grantedAt(snap, resource, operation, row.effectiveFrom,
		&forcedChange{kind: "binding", seq: row.seq, on: postEventOn(row.event)})
	return HistoryEvent{
		Event:         row.event,
		OccurredAt:    row.occurredAt,
		EffectiveFrom: row.effectiveFrom,
		EffectiveTo:   effectiveToPointer(row.effectiveTo),
		Role:          nullable(row.roleID),
		Granted:       granted,
		seq:           row.seq,
	}
}

func eventFromRolePerm(snap *snapshot, row rolePermRow, resource, operation string) HistoryEvent {
	granted := grantedAt(snap, resource, operation, row.effectiveFrom,
		&forcedChange{kind: "rolePerm", seq: row.seq, on: postEventOn(row.event)})
	return HistoryEvent{
		Event:         row.event,
		OccurredAt:    row.occurredAt,
		EffectiveFrom: row.effectiveFrom,
		EffectiveTo:   effectiveToPointer(row.effectiveTo),
		Role:          nullable(row.roleID),
		Permission:    nullable(row.permissionID),
		Granted:       granted,
		seq:           row.seq,
	}
}

func eventFromScope(snap *snapshot, row scopeRow, resource, operation string) HistoryEvent {
	granted := grantedAt(snap, resource, operation, row.effectiveFrom,
		&forcedChange{kind: "scope", seq: row.seq, on: postEventOn(row.event)})
	role := nullable(row.roleID)
	permission := nullable(row.permissionID)
	return HistoryEvent{
		Event:         row.event,
		OccurredAt:    row.occurredAt,
		EffectiveFrom: row.effectiveFrom,
		EffectiveTo:   effectiveToPointer(row.effectiveTo),
		Role:          role,
		Permission:    permission,
		Scope:         nullable(row.scope.text),
		Granted:       granted,
		seq:           row.seq,
	}
}
