package authz

import "strings"

// Input identifies the triple a caller asks about.
type Input struct {
	Subject   string
	Resource  string
	Operation string
}

// path is one structurally complete authorization chain with a window.
type path struct {
	role   string
	via    string
	perm   string
	scope  Scope
	from   int64
	to     int64
	hasTo  bool
	reason string
	seq    int64
}

// activeAt reports whether a half-open interval [from, to) is in force at at.
func activeAt(from int64, hasTo bool, to, at int64) bool {
	if from > at {
		return false
	}
	if hasTo && to <= at {
		return false
	}
	return true
}

// intersect returns the overlap of two half-open intervals plus whether they
// overlap. Open ends are represented by hasTo==false.
func intersect(aFrom int64, aHasTo bool, aTo, bFrom int64, bHasTo bool, bTo int64) (int64, bool, int64, bool) {
	from := aFrom
	if bFrom > from {
		from = bFrom
	}
	if !aHasTo {
		if !bHasTo {
			return from, false, 0, true
		}
		return from, true, bTo, from < bTo
	}
	if !bHasTo {
		return from, true, aTo, from < aTo
	}
	to := aTo
	if bTo < to {
		to = bTo
	}
	return from, true, to, from < to
}

// ScopeCovers reports whether scope covers the resource id.
//
// exact  : scope value equals the resource id.
// prefix : scope value is a hierarchy segment ending in "/"; the resource id
//
//	equals the segment without its slash or sits below it. "team-a/" never
//	matches "team-abc", and an empty prefix is rejected.
//
// all    : every resource is covered; scope value must be empty.
func ScopeCovers(scope Scope, resourceID string) bool {
	switch scope.Kind {
	case ScopeExact:
		return scope.Value == resourceID
	case ScopePrefix:
		if scope.Value == "" || !strings.HasSuffix(scope.Value, "/") {
			return false
		}
		base := strings.TrimSuffix(scope.Value, "/")
		return resourceID == base || strings.HasPrefix(resourceID, scope.Value)
	case ScopeAll:
		return scope.Value == ""
	default:
		return false
	}
}

// ValidScope reports whether kind/value form a well-formed stored scope.
func ValidScope(kind, value string) bool {
	switch kind {
	case ScopeExact, ScopePrefix:
		return value != ""
	case ScopeAll:
		return value == ""
	default:
		return false
	}
}

func moreSpecific(a, b path) bool {
	if rank := scopeKindRank(a.scope.Kind) - scopeKindRank(b.scope.Kind); rank != 0 {
		return rank < 0
	}
	if len(a.scope.Value) != len(b.scope.Value) {
		return len(a.scope.Value) > len(b.scope.Value)
	}
	if a.scope.Value != b.scope.Value {
		return a.scope.Value < b.scope.Value
	}
	if a.role != b.role {
		return a.role < b.role
	}
	if a.perm != b.perm {
		return a.perm < b.perm
	}
	return a.via < b.via
}

func scopeKindRank(kind string) int {
	switch kind {
	case ScopeExact:
		return 0
	case ScopePrefix:
		return 1
	case ScopeAll:
		return 2
	default:
		return 3
	}
}
