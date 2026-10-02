package api

import (
	"encoding/json"
	"net/http"
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

func subjectsList(h *apiHarness, target string) []any {
	h.t.Helper()
	response := resourceSubjects(h, target)
	items, ok := response["subjects"].([]any)
	if !ok {
		h.t.Fatalf("missing subjects list: %v", response)
	}
	return items
}

func wantPath(source string, boundRole, role any, permission, scope string) map[string]any {
	return map[string]any{
		"source":     source,
		"boundRole":  boundRole,
		"role":       role,
		"permission": permission,
		"scope":      scope,
	}
}

func wantSubjectPaths(subject string, paths ...any) map[string]any {
	return map[string]any{"subject": subject, "paths": paths}
}

// seedSubjectGraph builds viewer -> base plus editor, doc-read -> read and
// perm-b -> {read, write}, and three subjects: user-1 with role-derived and
// direct paths, user-2 whose scope sits on the inherited role base, and
// user-3 with a binding but no scope, who must never be listed.
func seedSubjectGraph(h *apiHarness) {
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-3", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/editor", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/perm-b", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/perm-b/operations",
		map[string]any{"operations": []string{"write", "read"}}), http.StatusOK)

	grantAt(h, "/roles/viewer/permissions/doc-read", nil)
	grantAt(h, "/roles/editor/permissions/doc-read", nil)
	grantAt(h, "/roles/base/permissions/doc-read", nil)
	grantAt(h, "/roles/base/permissions/perm-b", nil)

	grantAt(h, "/subjects/user-1/bindings/viewer", nil)
	grantAt(h, "/subjects/user-1/bindings/editor", nil)
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "viewer", "scope": "tenant-a/*"})
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "editor", "scope": "*"})
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1"})

	grantAt(h, "/subjects/user-2/bindings/viewer", nil)
	grantAt(h, "/subjects/user-2/scopes", map[string]any{"role": "base", "scope": "tenant-a/*"})

	grantAt(h, "/subjects/user-3/bindings/editor", nil)
}

func TestResourceSubjectsListsGrantingSubjects(t *testing.T) {
	h := newHarness(t)
	seedSubjectGraph(h)

	view := resourceSubjects(h, "/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z")
	if view["effectiveAt"] != "2026-02-01T00:00:00Z" || view["resource"] != "tenant-a/doc-1" || view["operation"] != "read" {
		t.Fatalf("view header = %v", view)
	}
	want := []any{
		wantSubjectPaths("user-1",
			wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1"),
			wantPath("ROLE", "editor", "editor", "doc-read", "*"),
			wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*"),
		),
		wantSubjectPaths("user-2",
			wantPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*"),
			wantPath("ROLE", "viewer", "base", "perm-b", "tenant-a/*"),
		),
	}
	if !reflect.DeepEqual(view["subjects"], want) {
		got, _ := json.Marshal(view["subjects"])
		t.Fatalf("subjects = %s", got)
	}

	// doc-read does not cover write; only user-2's perm-b path remains.
	got := subjectsList(h, "/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=write&effectiveAt=2026-02-01T00:00:00Z")
	want = []any{wantSubjectPaths("user-2",
		wantPath("ROLE", "viewer", "base", "perm-b", "tenant-a/*"),
	)}
	if !reflect.DeepEqual(got, want) {
		raw, _ := json.Marshal(got)
		t.Fatalf("write subjects = %s", raw)
	}

	// tenant-b/doc-2 is outside tenant-a/* and the exact grant; only the
	// wildcard scope on editor still covers it.
	got = subjectsList(h, "/resources/"+enc("tenant-b/doc-2")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z")
	want = []any{wantSubjectPaths("user-1",
		wantPath("ROLE", "editor", "editor", "doc-read", "*"),
	)}
	if !reflect.DeepEqual(got, want) {
		raw, _ := json.Marshal(got)
		t.Fatalf("tenant-b subjects = %s", raw)
	}
}

func TestResourceSubjectsRequiresAllThreeLayers(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-02-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)

	target := "/resources/" + enc("tenant-a/doc-1") + "/subjects?operation=read&effectiveAt="
	for _, when := range []string{"2026-01-15T00:00:00Z", "2026-02-15T00:00:00Z"} {
		if got := subjectsList(h, target+when); len(got) != 0 {
			t.Fatalf("subjects at %s = %v, want empty", when, got)
		}
	}
	got := subjectsList(h, target+"2026-03-15T00:00:00Z")
	want := []any{wantSubjectPaths("user-1",
		wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*"),
	)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subjects = %v, want %v", got, want)
	}
}

func TestResourceSubjectsEmptyListShapeAndReadOnly(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	recorder := h.request(http.MethodGet,
		"/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z", nil)
	h.mustStatus(recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"subjects":[]`) {
		t.Fatalf("empty body = %s", recorder.Body.String())
	}

	// The reverse query never writes history.
	recorder = h.request(http.MethodGet,
		"/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=read", nil)
	h.mustStatus(recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"events":[]`) {
		t.Fatalf("history after query = %s", recorder.Body.String())
	}
}

func TestResourceSubjectsDeduplicatesOverlappingVersions(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	grantAt(h, "/subjects/user-1/bindings/viewer", nil)
	grantAt(h, "/roles/viewer/permissions/doc-read", nil)
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "viewer", "scope": "tenant-a/*"})

	// Close the binding in June, then open a second interval backdated to
	// March: at April both versions are active but the path is listed once.
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)

	got := subjectsList(h, "/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2026-04-01T00:00:00Z")
	want := []any{wantSubjectPaths("user-1",
		wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*"),
	)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subjects = %v, want %v", got, want)
	}
}

func TestResourceSubjectsDefaultsToCurrentTime(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)

	got := subjectsList(h, "/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read")
	if len(got) != 1 {
		t.Fatalf("subjects = %v, want one subject", got)
	}
}

func TestResourceSubjectsSubjectIdentifierWithSlash(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/"+enc("team-a/user-2"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/"+enc("team-a/user-2")+"/scopes",
		map[string]any{"permission": "doc-read", "scope": "*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	got := subjectsList(h, "/resources/"+enc("tenant-a/doc-1")+"/subjects?operation=read&effectiveAt=2026-02-01T00:00:00Z")
	want := []any{wantSubjectPaths("team-a/user-2",
		wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "*"),
	)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subjects = %v, want %v", got, want)
	}
}

func TestResourceSubjectsErrorContract(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	expectError := func(target string, wantStatus int, wantType, wantField string) {
		t.Helper()
		recorder := h.request(http.MethodGet, target, nil)
		h.mustStatus(recorder, wantStatus)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		if errorObject["type"] != wantType || errorObject["field"] != wantField {
			t.Fatalf("error = %v, want %s/%s", errorObject, wantType, wantField)
		}
	}

	resource := "/resources/" + enc("tenant-a/doc-1") + "/subjects"
	expectError("/resources/ghost/subjects?operation=read", http.StatusNotFound, "NOT_FOUND", "resource")
	expectError("/resources/bad%20id/subjects?operation=read", http.StatusBadRequest, "INVALID_REQUEST", "resource")
	expectError(resource, http.StatusBadRequest, "INVALID_REQUEST", "operation")
	expectError(resource+"?operation=bad%20op", http.StatusBadRequest, "INVALID_REQUEST", "operation")
	expectError(resource+"?operation=ghost", http.StatusNotFound, "NOT_FOUND", "operation")
	expectError(resource+"?operation=read&effectiveAt=not-a-time", http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	// A malformed effectiveAt is the sole failure even when every other
	// parameter is invalid as well.
	expectError("/resources/ghost/subjects?effectiveAt=not-a-time", http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	// An invalid resource identifier outranks a missing operation.
	expectError("/resources/bad%20id/subjects", http.StatusBadRequest, "INVALID_REQUEST", "resource")
}
