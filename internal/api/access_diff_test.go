package api

import (
	"net/http"
	"reflect"
	"testing"
)

// seedAccessDiff builds: user-1 bound to viewer (parent base), with a role
// scope on tenant-a/* effective from 2026-01-01; a direct permission scope on
// tenant-b/doc-2 follows at 2026-03-01.
func seedAccessDiff(h *apiHarness) {
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-b/doc-2", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)
}

func diffResponse(h *apiHarness, target string) map[string]any {
	h.t.Helper()
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	return mustJSON(h.t, recorder)
}

func TestAccessDiffClassifiesAddedRemovedUnchanged(t *testing.T) {
	h := newHarness(t)
	seedAccessDiff(h)

	response := diffResponse(h, "/subjects/user-1/access/diff?from=2026-02-01T00:00:00Z&to=2026-04-01T00:00:00Z")
	if response["from"] != "2026-02-01T00:00:00Z" || response["to"] != "2026-04-01T00:00:00Z" {
		t.Fatalf("echoed range = %v", response)
	}
	rolePath := wantItem("ROLE", "viewer", "base", "doc-read", []any{"read"}, "tenant-a/*")
	directPath := wantItem("DIRECT_PERMISSION", nil, nil, "doc-read", []any{"read"}, "tenant-b/doc-2")

	if got := response["added"]; !reflect.DeepEqual(got, []any{directPath}) {
		t.Fatalf("added = %v", got)
	}
	if got := response["removed"]; !reflect.DeepEqual(got, []any{}) {
		t.Fatalf("removed = %v", got)
	}
	if got := response["unchanged"]; !reflect.DeepEqual(got, []any{rolePath}) {
		t.Fatalf("unchanged = %v", got)
	}
}

func TestAccessDiffReportsRemovedAfterRevoke(t *testing.T) {
	h := newHarness(t)
	seedAccessDiff(h)
	// Close the role scope halfway through the window.
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-03-15T00:00:00Z"}), http.StatusOK)

	response := diffResponse(h, "/subjects/user-1/access/diff?from=2026-02-01T00:00:00Z&to=2026-04-01T00:00:00Z")
	rolePath := wantItem("ROLE", "viewer", "base", "doc-read", []any{"read"}, "tenant-a/*")
	directPath := wantItem("DIRECT_PERMISSION", nil, nil, "doc-read", []any{"read"}, "tenant-b/doc-2")
	if got := response["removed"]; !reflect.DeepEqual(got, []any{rolePath}) {
		t.Fatalf("removed = %v", got)
	}
	if got := response["added"]; !reflect.DeepEqual(got, []any{directPath}) {
		t.Fatalf("added = %v", got)
	}
	if got := response["unchanged"].([]any); len(got) != 0 {
		t.Fatalf("unchanged = %v", got)
	}
}

func TestAccessDiffEqualMomentsIsUnchanged(t *testing.T) {
	h := newHarness(t)
	seedAccessDiff(h)

	response := diffResponse(h, "/subjects/user-1/access/diff?from=2026-04-01T00:00:00Z&to=2026-04-01T00:00:00Z")
	rolePath := wantItem("ROLE", "viewer", "base", "doc-read", []any{"read"}, "tenant-a/*")
	directPath := wantItem("DIRECT_PERMISSION", nil, nil, "doc-read", []any{"read"}, "tenant-b/doc-2")
	if got := response["unchanged"]; !reflect.DeepEqual(got, []any{directPath, rolePath}) {
		t.Fatalf("unchanged = %v", got)
	}
	if got := response["added"]; len(got.([]any)) != 0 {
		t.Fatalf("added = %v", got)
	}
	if got := response["removed"]; len(got.([]any)) != 0 {
		t.Fatalf("removed = %v", got)
	}
}

func TestAccessDiffNormalizesToUTC(t *testing.T) {
	h := newHarness(t)
	seedAccessDiff(h)

	response := diffResponse(h, "/subjects/user-1/access/diff?from=2026-02-01T08%3A00%3A00%2B08%3A00&to=2026-04-01T08%3A00%3A00%2B08%3A00")
	if response["from"] != "2026-02-01T00:00:00Z" || response["to"] != "2026-04-01T00:00:00Z" {
		t.Fatalf("range not normalized to UTC: %v", response)
	}
}

func TestAccessDiffHalfOpenInterval(t *testing.T) {
	h := newHarness(t)
	seedAccessDiff(h)

	// The direct scope opens at 2026-03-01T00:00:00Z. One second before it is
	// absent; at the opening instant it is present.
	before := diffResponse(h, "/subjects/user-1/access/diff?from=2026-02-28T23:59:59Z&to=2026-02-28T23:59:59Z")
	if got := before["added"].([]any); len(got) != 0 || len(before["unchanged"].([]any)) != 1 {
		t.Fatalf("pre-open diff = %v", before)
	}
	atOpen := diffResponse(h, "/subjects/user-1/access/diff?from=2026-02-28T23:59:59Z&to=2026-03-01T00:00:00Z")
	if got := atOpen["added"].([]any); len(got) != 1 {
		t.Fatalf("at-open added = %v", atOpen)
	}
}

func TestAccessDiffEmptyArraysWhenNoPaths(t *testing.T) {
	h := newHarness(t)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1", nil), http.StatusOK)
	response := diffResponse(h, "/subjects/user-1/access/diff?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z")
	for _, key := range []string{"added", "removed", "unchanged"} {
		if got := response[key].([]any); len(got) != 0 {
			t.Fatalf("%s = %v, want empty", key, got)
		}
	}
}

func TestAccessDiffErrorContract(t *testing.T) {
	h := newHarness(t)
	seedAccessDiff(h)

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

	base := "/subjects/user-1/access/diff"
	expectError(base+"?to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "from")
	expectError(base+"?from=&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "from")
	expectError(base+"?from=2026-01-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "to")
	expectError(base+"?from=2026-01-01T00:00:00Z&to=", http.StatusBadRequest, "INVALID_REQUEST", "to")
	expectError(base+"?from=nope&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")
	expectError(base+"?from=2026-01-01T00:00:00Z&to=nope", http.StatusBadRequest, "INVALID_TIME", "to")
	// from wins over to when both are invalid.
	expectError(base+"?from=nope&to=nope", http.StatusBadRequest, "INVALID_TIME", "from")
	expectRangeError(base + "?from=2026-03-01T00:00:00Z&to=2026-01-01T00:00:00Z")
	// Time validation outranks subject checks.
	expectError("/subjects/bad%20id/access/diff?from=nope&to=2026-01-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")
	expectError("/subjects/ghost/access/diff?from=nope&to=2026-01-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")
	expectError("/subjects/bad%20id/access/diff?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_REQUEST", "subject")
	expectError("/subjects/ghost/access/diff?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusNotFound, "NOT_FOUND", "subject")
}
