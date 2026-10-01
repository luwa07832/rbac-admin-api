package authz

import (
	"regexp"
	"strings"
)

const maxIdentifierLength = 128

var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]*$`)

type scopeKind int

const (
	scopeExact scopeKind = iota
	scopePrefix
	scopeAll
)

// scopeRef keeps the original scope text alongside its parsed form so the
// effective scope in a decision is always reported using the stored boundary.
type scopeRef struct {
	text   string
	kind   scopeKind
	prefix string
}

// parseScope accepts the existing scope boundary grammar:
//
//	"*"               matches every resource;
//	"prefix/*"        matches resources equal to "prefix" or under "prefix/";
//	anything else     matches that one resource exactly.
func parseScope(scope string) (scopeRef, bool) {
	if scope == "*" {
		return scopeRef{text: scope, kind: scopeAll}, true
	}
	if strings.HasSuffix(scope, "/*") {
		prefix := strings.TrimSuffix(scope, "/*")
		if prefix == "" || !validIdentifier(prefix) || strings.Contains(prefix, "*") {
			return scopeRef{}, false
		}
		return scopeRef{text: scope, kind: scopePrefix, prefix: prefix}, true
	}
	if strings.Contains(scope, "*") || !validIdentifier(scope) {
		return scopeRef{}, false
	}
	return scopeRef{text: scope, kind: scopeExact, prefix: scope}, true
}

func (s scopeRef) matches(resource string) bool {
	switch s.kind {
	case scopeAll:
		return true
	case scopeExact:
		return s.prefix == resource
	case scopePrefix:
		return strings.HasPrefix(resource, s.prefix+"/")
	}
	return false
}

// compareScope orders scopes from most to least specific: exact match, then
// longest prefix, then the wildcard.
func compareScope(a, b scopeRef) int {
	if a.kind != b.kind {
		if a.kind < b.kind {
			return -1
		}
		return 1
	}
	if a.kind == scopePrefix && len(a.prefix) != len(b.prefix) {
		if len(a.prefix) > len(b.prefix) {
			return -1
		}
		return 1
	}
	return strings.Compare(a.text, b.text)
}

// validIdentifier is the single grammar every identifier must satisfy.
// Hierarchical identifiers may use "/" between non-empty segments.
func validIdentifier(value string) bool {
	if value == "" || len(value) > maxIdentifierLength {
		return false
	}
	if strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || !segmentPattern.MatchString(segment) {
			return false
		}
	}
	return true
}
