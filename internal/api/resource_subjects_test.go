package api

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func resourceSubjects(h *apiHarness, target string) map[string]any {
	h.t.Helper()
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	return mustJSON(h.t, recorder)
}

func subjectPath(source string, boundRole, role any, permission, scope string) map[string]any {
	return map[string]any{
		"source":     source,
		"boundRole":  boundRole,
		"role":       role,
		"permission": permission,
		"scope":      scope,
	}
}

// seedReverseQuery builds two roles (viewer inherits base), two permissions
// (doc-read -> read, doc-write -> write) and three subjects:
// alice has an inherited role path plus a direct permission; bob has only a
// direct permission on another resource; carol holds structurally identical
// grants whose intervals stay closed at the query instant.
func seedReverseQuery(h *apiHarness) {
	for _, target := range []string{
		"/subjects/alice", "/subjects/bob", "/subjects/carol",
		"/resources/" + enc("tenant-a/doc-1"),
		"/resources/" + enc("tenant-a/doc-2"),
		"/resources/" + enc("tenant-c/doc-9"),
		"/operations/read", "/operations/write",
		"/roles/base", "/roles/viewer",
		"/permissions/doc-read", "/permissions/doc-write",
	} {
		h.mustStatus(h.request(http.MethodPut, target, nil), http.StatusOK)
	}
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read/operations",
		map[string]any{"operations": []string{"read"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-write/operations",
		map[string]any{"operations": []string{"write"}}), http.StatusOK)

	grantAt(h, "/subjects/alice/bindings/viewer", nil)
	grantAt(h, "/subjects/bob/bindings/viewer", nil)
	grantAt(h, "/roles/base/permissions/doc-read", nil)
	grantAt(h, "/subjects/alice/scopes", map[string]any{"role": "base", "scope": "tenant-a/*"})
	grantAt(h, "/subjects/bob/scopes", map[string]any{"role": "base", "scope": "tenant-b/*"})
	grantAt(h, "/subjects/alice/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-2"})
	grantAt(h, "/subjects/bob/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1"})
}

func TestResourceSubjectsListsEffectiveSubjects(t *testing.T) {
	h := newHarness(t)
	seedReverseQuery(h)

	response := resourceSubjects(h,
		"/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z")
	if response["effectiveAt"] != "2026-02-01T00:00:00Z" ||
		response["resource"] != "tenant-a/doc-1" || response["operation"] != "read" {
		t.Fatalf("unexpected envelope: %v", response)
	}
	subjects := response["subjects"].([]any)
	want := []any{
		map[string]any{
			"subject": "alice",
			"paths": []any{
				subjectPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*"),
			},
		},
		map[string]any{
			"subject": "bob",
			"paths": []any{
				subjectPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1"),
			},
		},
	}
	if !reflect.DeepEqual(subjects, want) {
		t.Fatalf("subjects = %v, want %v", subjects, want)
	}
}

func TestResourceSubjectsScopePatternsAndOperation(t *testing.T) {
	h := newHarness(t)
	seedReverseQuery(h)
	// A wildcard scope grants on any resource; an unrelated operation and a
	// resource outside the prefix must not surface the subject.
	grantAt(h, "/subjects/carol/scopes", map[string]any{"role": "base", "scope": "*"})
	grantAt(h, "/subjects/carol/bindings/viewer", nil)

	doc9 := resourceSubjects(h,
		"/resources/"+enc("tenant-c/doc-9")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z")
	subjects := doc9["subjects"].([]any)
	if len(subjects) != 1 || subjects[0].(map[string]any)["subject"] != "carol" {
		t.Fatalf("wildcard subjects = %v", subjects)
	}

	// doc-write covers write only; nobody carries it on doc-1.
	writeOnly := resourceSubjects(h,
		"/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=write&effectiveAt=2026-02-01T00:00:00Z")
	if subjects := writeOnly["subjects"].([]any); len(subjects) != 0 {
		t.Fatalf("write subjects = %v, want empty", subjects)
	}

	// doc-2: alice matches through the tenant-a/* role path and the exact
	// direct scope, carol through the wildcard, while bob's exact tenant-a/doc-1
	// direct scope and tenant-b/* role scope both miss.
	doc2 := resourceSubjects(h,
		"/resources/"+enc("tenant-a/doc-2")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z")
	got := []string{}
	for _, entry := range doc2["subjects"].([]any) {
		got = append(got, entry.(map[string]any)["subject"].(string))
	}
	if !reflect.DeepEqual(got, []string{"alice", "carol"}) {
		t.Fatalf("doc-2 subjects = %v, want [alice carol]", got)
	}
}

func TestResourceSubjectsEmptyResultShape(t *testing.T) {
	h := newHarness(t)
	seedReverseQuery(h)
	recorder := h.request(http.MethodGet,
		"/resources/"+enc("tenant-c/doc-9")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z", nil)
	h.mustStatus(recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"subjects":[]`) {
		t.Fatalf("empty body = %s", recorder.Body.String())
	}
}

func TestResourceSubjectsRespectsIntervalsAndInheritance(t *testing.T) {
	h := newHarness(t)
	seedReverseQuery(h)

	// Before any interval opened nobody is effective.
	before := resourceSubjects(h,
		"/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2025-12-01T00:00:00Z")
	if subjects := before["subjects"].([]any); len(subjects) != 0 {
		t.Fatalf("pre-grant subjects = %v", subjects)
	}

	// carol's binding opens in May while its scope already existed: before the
	// binding there is no role chain, so carol stays absent.
	grantAt(h, "/subjects/carol/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-05-01T00:00:00Z"})
	grantAt(h, "/subjects/carol/scopes", map[string]any{"role": "base", "scope": "*"})
	april := resourceSubjects(h,
		"/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2026-04-01T00:00:00Z")
	for _, entry := range april["subjects"].([]any) {
		if entry.(map[string]any)["subject"] == "carol" {
			t.Fatalf("carol listed before the binding opened: %v", april["subjects"])
		}
	}
	june := resourceSubjects(h,
		"/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2026-06-01T00:00:00Z")
	found := false
	for _, entry := range june["subjects"].([]any) {
		if entry.(map[string]any)["subject"] == "carol" {
			found = true
		}
	}
	if !found {
		t.Fatalf("carol missing after the binding opened: %v", june["subjects"])
	}
}

func TestResourceSubjectsSortsPaths(t *testing.T) {
	h := newHarness(t)
	seedReverseQuery(h)
	grantAt(h, "/roles/viewer/permissions/doc-read", nil)
	grantAt(h, "/subjects/alice/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/doc-1"})

	response := resourceSubjects(h,
		"/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z")
	alice := response["subjects"].([]any)[0].(map[string]any)
	paths := alice["paths"].([]any)
	want := []any{
		subjectPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*"),
		subjectPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/doc-1"),
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
}

func TestResourceSubjectsErrorContract(t *testing.T) {
	h := newHarness(t)
	seedReverseQuery(h)

	expectError := func(target string, wantStatus int, wantType, wantField string) {
		t.Helper()
		recorder := h.request(http.MethodGet, target, nil)
		h.mustStatus(recorder, wantStatus)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		if errorObject["type"] != wantType || errorObject["field"] != wantField {
			t.Fatalf("error = %v, want %s/%s", errorObject, wantType, wantField)
		}
	}

	doc1 := enc("tenant-a/doc-1")
	// effectiveAt outranks resource and operation checks.
	expectError("/resources/"+doc1+"/subjects?operation=read&effectiveAt=not-a-time",
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	expectError("/resources/ghost/subjects?operation=read&effectiveAt=not-a-time",
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	// Resource grammar precedes operation checks.
	expectError("/resources/bad%20id/subjects?operation=read",
		http.StatusBadRequest, "INVALID_REQUEST", "resource")
	// Valid-but-unknown resource precedes operation validation.
	expectError("/resources/ghost/subjects?operation=read",
		http.StatusNotFound, "NOT_FOUND", "resource")
	// Missing, malformed and unknown operation follow in that order.
	expectError("/resources/"+doc1+"/subjects",
		http.StatusBadRequest, "INVALID_REQUEST", "operation")
	expectError("/resources/"+doc1+"/subjects?operation=bad%20op",
		http.StatusBadRequest, "INVALID_REQUEST", "operation")
	expectError("/resources/"+doc1+"/subjects?operation=ghost",
		http.StatusNotFound, "NOT_FOUND", "operation")
}

func TestResourceSubjectsIsReadOnly(t *testing.T) {
	h := newHarness(t)
	seedReverseQuery(h)
	target := "/resources/" + enc("tenant-a/doc-1") +
		"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z"
	before := h.request(http.MethodGet, "/history?subject=alice&resource="+
		url.QueryEscape("tenant-a/doc-1")+"&operation=read", nil)
	h.mustStatus(before, http.StatusOK)
	h.mustStatus(h.request(http.MethodGet, target, nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodGet, target, nil), http.StatusOK)
	after := h.request(http.MethodGet, "/history?subject=alice&resource="+
		url.QueryEscape("tenant-a/doc-1")+"&operation=read", nil)
	h.mustStatus(after, http.StatusOK)
	if before.Body.String() != after.Body.String() {
		t.Fatalf("history changed after reverse query:\nbefore=%s\nafter=%s",
			before.Body.String(), after.Body.String())
	}
}
