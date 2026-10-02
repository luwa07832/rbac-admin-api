package api

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func resourceSubjectsDiff(h *apiHarness, target string) map[string]any {
	h.t.Helper()
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	return mustJSON(h.t, recorder)
}

func wantSubjectDiff(subject string, added, removed, unchanged []any) map[string]any {
	return map[string]any{
		"subject":   subject,
		"added":     added,
		"removed":   removed,
		"unchanged": unchanged,
	}
}

// seedSubjectDiff builds a timeline against tenant-a/doc-1 + read:
// user-1 has a role path throughout plus a direct scope opening 2026-03-01
// and a wildcard role scope closing 2026-03-15; user-2 only carries a path
// from 2026-03-01; user-3 loses its sole path on 2026-03-15; user-4 never
// has a covering path.
func seedSubjectDiff(h *apiHarness) {
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-3", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-4", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/editor", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)

	grantAt(h, "/roles/base/permissions/doc-read", nil)
	grantAt(h, "/roles/editor/permissions/doc-read", nil)

	// user-1: bound to viewer throughout; role scope on tenant-a/*
	// throughout; wildcard editor scope until 2026-03-15; direct scope on
	// tenant-a/doc-1 from 2026-03-01.
	grantAt(h, "/subjects/user-1/bindings/viewer", nil)
	grantAt(h, "/subjects/user-1/bindings/editor", nil)
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "base", "scope": "tenant-a/*"})
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "editor", "scope": "*"})
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/scopes",
		map[string]any{"role": "editor", "scope": "*", "effectiveFrom": "2026-03-15T00:00:00Z"}), http.StatusOK)

	// user-2: direct scope appears on 2026-03-01; the binding existing from
	// January has no matching scope before then.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/*", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)

	// user-3: sole direct path closes on 2026-03-15.
	grantAt(h, "/subjects/user-3/scopes", map[string]any{"permission": "doc-read", "scope": "*"})
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-3/scopes",
		map[string]any{"permission": "doc-read", "scope": "*", "effectiveFrom": "2026-03-15T00:00:00Z"}), http.StatusOK)
}

func diffTarget() string {
	return "/resources/" + enc("tenant-a/doc-1") + "/subjects/diff"
}

func TestResourceSubjectsDiffClassifiesPerSubject(t *testing.T) {
	h := newHarness(t)
	seedSubjectDiff(h)

	response := resourceSubjectsDiff(h,
		diffTarget()+"?operation=read&from=2026-02-01T00:00:00Z&to=2026-04-01T00:00:00Z")
	if response["from"] != "2026-02-01T00:00:00Z" ||
		response["to"] != "2026-04-01T00:00:00Z" ||
		response["resource"] != "tenant-a/doc-1" ||
		response["operation"] != "read" {
		t.Fatalf("view header = %v", response)
	}

	roleBase := wantPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*")
	roleEditor := wantPath("ROLE", "editor", "editor", "doc-read", "*")
	directExact := wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1")
	directPrefix := wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/*")
	directAll := wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "*")

	want := []any{
		wantSubjectDiff("user-1",
			[]any{directExact},
			[]any{roleEditor},
			[]any{roleBase},
		),
		wantSubjectDiff("user-2",
			[]any{directPrefix},
			[]any{},
			[]any{},
		),
		wantSubjectDiff("user-3",
			[]any{},
			[]any{directAll},
			[]any{},
		),
	}
	if !reflect.DeepEqual(response["subjects"], want) {
		t.Fatalf("subjects = %#v, want %#v", response["subjects"], want)
	}
}

func TestResourceSubjectsDiffEqualMomentsAllUnchanged(t *testing.T) {
	h := newHarness(t)
	seedSubjectDiff(h)

	response := resourceSubjectsDiff(h,
		diffTarget()+"?operation=read&from=2026-04-01T00:00:00Z&to=2026-04-01T00:00:00Z")
	roleBase := wantPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*")
	directExact := wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1")
	directPrefix := wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/*")

	want := []any{
		wantSubjectDiff("user-1", []any{}, []any{}, []any{directExact, roleBase}),
		wantSubjectDiff("user-2", []any{}, []any{}, []any{directPrefix}),
	}
	if !reflect.DeepEqual(response["subjects"], want) {
		t.Fatalf("subjects = %#v, want %#v", response["subjects"], want)
	}
}

func TestResourceSubjectsDiffNormalizesToUTC(t *testing.T) {
	h := newHarness(t)
	seedSubjectDiff(h)

	response := resourceSubjectsDiff(h,
		diffTarget()+"?operation=read&from=2026-02-01T08%3A00%3A00%2B08%3A00&to=2026-04-01T08%3A00%3A00%2B08%3A00")
	if response["from"] != "2026-02-01T00:00:00Z" || response["to"] != "2026-04-01T00:00:00Z" {
		t.Fatalf("range not normalized to UTC: %v", response)
	}
}

func TestResourceSubjectsDiffHalfOpenInterval(t *testing.T) {
	h := newHarness(t)
	seedSubjectDiff(h)

	// The user-2 direct scope opens at 2026-03-01T00:00:00Z. One second
	// before the diff shows user-2 with an empty unchanged list only through
	// other subjects; at the opening instant it appears in user-2's added.
	preOpen := resourceSubjectsDiff(h,
		diffTarget()+"?operation=read&from=2026-02-28T23:59:59Z&to=2026-02-28T23:59:59Z")
	for _, raw := range preOpen["subjects"].([]any) {
		subject := raw.(map[string]any)
		if subject["subject"] == "user-2" {
			t.Fatalf("user-2 listed before scope opened: %v", subject)
		}
	}
	atOpen := resourceSubjectsDiff(h,
		diffTarget()+"?operation=read&from=2026-02-28T23:59:59Z&to=2026-03-01T00:00:00Z")
	var user2 map[string]any
	for _, raw := range atOpen["subjects"].([]any) {
		subject := raw.(map[string]any)
		if subject["subject"] == "user-2" {
			user2 = subject
		}
	}
	if user2 == nil || len(user2["added"].([]any)) != 1 {
		t.Fatalf("user-2 at open = %v", user2)
	}
}

func TestResourceSubjectsDiffEmptyListShapeAndReadOnly(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	recorder := h.request(http.MethodGet,
		diffTarget()+"?operation=read&from=2026-02-01T00:00:00Z&to=2026-04-01T00:00:00Z", nil)
	h.mustStatus(recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"subjects":[]`) {
		t.Fatalf("empty body = %s", recorder.Body.String())
	}

	// The diff query neither writes history nor changes a later decision.
	recorder = h.request(http.MethodGet,
		"/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=read", nil)
	h.mustStatus(recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"events":[]`) {
		t.Fatalf("history after diff = %s", recorder.Body.String())
	}
}

func TestResourceSubjectsDiffErrorContract(t *testing.T) {
	h := newHarness(t)
	seedSubjectDiff(h)

	expectError := func(target string, wantStatus int, wantType, wantField string) {
		t.Helper()
		recorder := h.request(http.MethodGet, target, nil)
		h.mustStatus(recorder, wantStatus)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		if errorObject["type"] != wantType || errorObject["field"] != wantField {
			t.Fatalf("error = %v, want %s/%s", errorObject, wantType, wantField)
		}
	}
	expectRangeError := func(target string) {
		t.Helper()
		recorder := h.request(http.MethodGet, target, nil)
		h.mustStatus(recorder, http.StatusBadRequest)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		if errorObject["type"] != "INVALID_RANGE" {
			t.Fatalf("error = %v, want INVALID_RANGE", errorObject)
		}
	}

	base := diffTarget()
	query := "operation=read"
	expectError(base+"?"+query+"&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "from")
	expectError(base+"?"+query+"&from=&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "from")
	expectError(base+"?"+query+"&from=2026-01-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "to")
	expectError(base+"?"+query+"&from=2026-01-01T00:00:00Z&to=", http.StatusBadRequest, "INVALID_REQUEST", "to")
	expectError(base+"?"+query+"&from=nope&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")
	expectError(base+"?"+query+"&from=2026-01-01T00:00:00Z&to=nope", http.StatusBadRequest, "INVALID_TIME", "to")
	expectError(base+"?"+query+"&from=nope&to=nope", http.StatusBadRequest, "INVALID_TIME", "from")
	expectRangeError(base + "?" + query + "&from=2026-03-01T00:00:00Z&to=2026-01-01T00:00:00Z")

	// Time validation outranks every resource/operation check.
	expectError("/resources/ghost/subjects/diff?"+query+"&from=nope&to=2026-01-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_TIME", "from")
	expectError("/resources/bad%20id/subjects/diff?from=nope&to=2026-01-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_TIME", "from")
	// After time validation, the resource identifier then operation.
	expectError("/resources/bad%20id/subjects/diff?"+query+"&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_REQUEST", "resource")
	expectError(base+"?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_REQUEST", "operation")
	expectError(base+"?operation=bad%20op&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_REQUEST", "operation")
	expectError("/resources/ghost/subjects/diff?"+query+"&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusNotFound, "NOT_FOUND", "resource")
	expectError(base+"?operation=ghost&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusNotFound, "NOT_FOUND", "operation")
}
