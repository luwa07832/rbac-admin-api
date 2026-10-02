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

// seedResourceDiff builds on tenant-a/doc-1 + read:
// user-1 keeps the viewer role path throughout and gains a direct permission
// path on 2026-03-01; user-2's inherited base path is revoked on 2026-03-15.
func seedResourceDiff(h *apiHarness) {
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)

	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)

	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-2/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-03-15T00:00:00Z"}), http.StatusOK)
}

func wantSubjectDiff(subject string, added, removed, unchanged []any) map[string]any {
	return map[string]any{
		"subject":   subject,
		"added":     added,
		"removed":   removed,
		"unchanged": unchanged,
	}
}

func TestResourceSubjectsDiffClassifies(t *testing.T) {
	h := newHarness(t)
	seedResourceDiff(h)

	directPath := wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1")
	viewerPath := wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*")
	basePath := wantPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*")

	target := "/resources/" + enc("tenant-a/doc-1") + "/subjects/diff?operation=read" +
		"&from=2026-02-01T00:00:00Z&to=2026-04-01T00:00:00Z"
	view := resourceSubjectsDiff(h, target)
	if view["from"] != "2026-02-01T00:00:00Z" || view["to"] != "2026-04-01T00:00:00Z" ||
		view["resource"] != "tenant-a/doc-1" || view["operation"] != "read" {
		t.Fatalf("view header = %v", view)
	}
	want := []any{
		wantSubjectDiff("user-1", []any{directPath}, []any{}, []any{viewerPath}),
		wantSubjectDiff("user-2", []any{}, []any{basePath}, []any{}),
	}
	if !reflect.DeepEqual(view["subjects"], want) {
		t.Fatalf("subjects = %v, want %v", view["subjects"], want)
	}
}

func TestResourceSubjectsDiffEqualMomentsAreUnchanged(t *testing.T) {
	h := newHarness(t)
	seedResourceDiff(h)

	directPath := wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1")
	viewerPath := wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*")

	target := "/resources/" + enc("tenant-a/doc-1") + "/subjects/diff?operation=read" +
		"&from=2026-04-01T00:00:00Z&to=2026-04-01T00:00:00Z"
	view := resourceSubjectsDiff(h, target)
	// user-2 has no path at this moment and must be absent; user-1's paths
	// are all unchanged and sorted by the published field sequence.
	want := []any{
		wantSubjectDiff("user-1", []any{}, []any{}, []any{directPath, viewerPath}),
	}
	if !reflect.DeepEqual(view["subjects"], want) {
		t.Fatalf("subjects = %v, want %v", view["subjects"], want)
	}
}

func TestResourceSubjectsDiffNormalizesToUTC(t *testing.T) {
	h := newHarness(t)
	seedResourceDiff(h)

	target := "/resources/" + enc("tenant-a/doc-1") + "/subjects/diff?operation=read" +
		"&from=2026-02-01T08%3A00%3A00%2B08%3A00&to=2026-04-01T08%3A00%3A00%2B08%3A00"
	view := resourceSubjectsDiff(h, target)
	if view["from"] != "2026-02-01T00:00:00Z" || view["to"] != "2026-04-01T00:00:00Z" {
		t.Fatalf("range not normalized to UTC: %v", view)
	}
}

func TestResourceSubjectsDiffHalfOpenInterval(t *testing.T) {
	h := newHarness(t)
	seedResourceDiff(h)

	prefix := "/resources/" + enc("tenant-a/doc-1") + "/subjects/diff?operation=read"
	// One second before the direct scope opens it is absent everywhere.
	before := resourceSubjectsDiff(h, prefix+"&from=2026-02-28T23:59:59Z&to=2026-02-28T23:59:59Z")
	for _, item := range before["subjects"].([]any) {
		subject := item.(map[string]any)
		if subject["subject"] == "user-1" && len(subject["added"].([]any)) != 0 {
			t.Fatalf("pre-open user-1 = %v", subject)
		}
	}
	// At the opening instant the path lands in added.
	atOpen := resourceSubjectsDiff(h, prefix+"&from=2026-02-28T23:59:59Z&to=2026-03-01T00:00:00Z")
	var userAdded []any
	for _, item := range atOpen["subjects"].([]any) {
		subject := item.(map[string]any)
		if subject["subject"] == "user-1" {
			userAdded = subject["added"].([]any)
		}
	}
	if len(userAdded) != 1 {
		t.Fatalf("at-open added = %v", userAdded)
	}
}

func TestResourceSubjectsDiffEmptyAndReadOnly(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	target := "/resources/" + enc("tenant-a/doc-1") + "/subjects/diff?operation=read" +
		"&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z"
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"subjects":[]`) {
		t.Fatalf("empty body = %s", recorder.Body.String())
	}

	// The diff query never writes history.
	recorder = h.request(http.MethodGet,
		"/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=read", nil)
	h.mustStatus(recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"events":[]`) {
		t.Fatalf("history after query = %s", recorder.Body.String())
	}
}

func TestResourceSubjectsDiffErrorContract(t *testing.T) {
	h := newHarness(t)
	seedResourceDiff(h)

	expectError := func(target string, wantStatus int, wantType, wantField string) {
		t.Helper()
		recorder := h.request(http.MethodGet, target, nil)
		h.mustStatus(recorder, wantStatus)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		if errorObject["type"] != wantType || errorObject["field"] != wantField {
			t.Fatalf("error = %v, want %s/%s", errorObject, wantType, wantField)
		}
	}
	expectRange := func(target string) {
		t.Helper()
		recorder := h.request(http.MethodGet, target, nil)
		h.mustStatus(recorder, http.StatusBadRequest)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		if errorObject["type"] != "INVALID_RANGE" {
			t.Fatalf("error = %v, want INVALID_RANGE", errorObject)
		}
	}

	base := "/resources/" + enc("tenant-a/doc-1") + "/subjects/diff"
	read := "?operation=read"
	expectError(base+read+"&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "from")
	expectError(base+read+"&from=&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "from")
	expectError(base+read+"&from=2026-01-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "to")
	expectError(base+read+"&from=2026-01-01T00:00:00Z&to=", http.StatusBadRequest, "INVALID_REQUEST", "to")
	expectError(base+read+"&from=nope&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")
	expectError(base+read+"&from=2026-01-01T00:00:00Z&to=nope", http.StatusBadRequest, "INVALID_TIME", "to")
	// from wins over to when both are invalid.
	expectError(base+read+"&from=nope&to=nope", http.StatusBadRequest, "INVALID_TIME", "from")
	expectRange(base + read + "&from=2026-03-01T00:00:00Z&to=2026-01-01T00:00:00Z")
	// Time validation outranks resource and operation checks.
	expectError("/resources/ghost/subjects/diff?from=nope&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_TIME", "from")
	expectError(base+"?from=nope&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_TIME", "from")
	expectError("/resources/bad%20id/subjects/diff?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_REQUEST", "resource")
	expectError(base+"?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_REQUEST", "operation")
	expectError(base+"?operation=bad%20op&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_REQUEST", "operation")
	// An invalid resource identifier outranks a missing operation.
	expectError("/resources/bad%20id/subjects/diff?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusBadRequest, "INVALID_REQUEST", "resource")
	expectError("/resources/ghost/subjects/diff?operation=read&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusNotFound, "NOT_FOUND", "resource")
	expectError(base+"?operation=ghost&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z",
		http.StatusNotFound, "NOT_FOUND", "operation")
}
