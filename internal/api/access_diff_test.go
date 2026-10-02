package api

import (
	"net/http"
	"reflect"
	"testing"
)

func diffView(h *apiHarness, target string) map[string]any {
	h.t.Helper()
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	body := mustJSON(h.t, recorder)
	for _, key := range []string{"from", "to", "added", "removed", "unchanged"} {
		if _, ok := body[key]; !ok {
			h.t.Fatalf("diff response missing %q: %s", key, recorder.Body.String())
		}
	}
	return body
}

func seedDiffSubject(h *apiHarness) {
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	// Role scope stays active across the whole window: unchanged path.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	// Direct permission scope opens inside the window: added path.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-b/doc-2", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)
	// Role scope on the exact resource closes at the "to" moment: because
	// intervals are half-open it is present at from but not at to.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-05-01T00:00:00Z"}), http.StatusOK)
}

func TestAccessDiffClassifiesAddedRemovedUnchanged(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedDiffSubject(h)

	body := diffView(h, "/subjects/user-1/access/diff?from=2026-02-01T00:00:00Z&to=2026-05-01T00:00:00Z")
	if body["from"] != "2026-02-01T00:00:00Z" || body["to"] != "2026-05-01T00:00:00Z" {
		t.Fatalf("echoed moments = %v / %v", body["from"], body["to"])
	}
	wantAdded := []any{
		wantItem("DIRECT_PERMISSION", nil, nil, "doc-read", []any{"read"}, "tenant-b/doc-2"),
	}
	wantRemoved := []any{
		wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "tenant-a/doc-1"),
	}
	wantUnchanged := []any{
		wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "tenant-a/*"),
	}
	if !reflect.DeepEqual(body["added"], wantAdded) {
		t.Fatalf("added = %v, want %v", body["added"], wantAdded)
	}
	if !reflect.DeepEqual(body["removed"], wantRemoved) {
		t.Fatalf("removed = %v, want %v", body["removed"], wantRemoved)
	}
	if !reflect.DeepEqual(body["unchanged"], wantUnchanged) {
		t.Fatalf("unchanged = %v, want %v", body["unchanged"], wantUnchanged)
	}
}

func TestAccessDiffEqualMomentsIsAllUnchanged(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedDiffSubject(h)

	body := diffView(h, "/subjects/user-1/access/diff?from=2026-02-01T00:00:00Z&to=2026-02-01T00:00:00Z")
	added := body["added"].([]any)
	removed := body["removed"].([]any)
	unchanged := body["unchanged"].([]any)
	if len(added) != 0 || len(removed) != 0 {
		t.Fatalf("equal moments produced changes: added=%v removed=%v", added, removed)
	}
	wantUnchanged := []any{
		wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "tenant-a/*"),
		wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "tenant-a/doc-1"),
	}
	if !reflect.DeepEqual(unchanged, wantUnchanged) {
		t.Fatalf("unchanged = %v, want %v", unchanged, wantUnchanged)
	}
}

func TestAccessDiffBeforeAnyGrantHasEmptyArrays(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedDiffSubject(h)

	body := diffView(h, "/subjects/user-1/access/diff?from=2025-12-01T00:00:00Z&to=2025-12-15T00:00:00Z")
	for _, key := range []string{"added", "removed", "unchanged"} {
		if items := body[key].([]any); len(items) != 0 {
			t.Fatalf("%s = %v, want empty", key, items)
		}
	}
}

func TestAccessDiffNormalizesMomentsToUTC(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedDiffSubject(h)

	body := diffView(h, "/subjects/user-1/access/diff?from=2026-02-01T08:00:00%2B08:00&to=2026-05-01T00:00:00Z")
	if body["from"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("from = %v, want normalized UTC", body["from"])
	}
	if body["to"] != "2026-05-01T00:00:00Z" {
		t.Fatalf("to = %v, want normalized UTC", body["to"])
	}
}

func TestAccessDiffKeepsStableOrdering(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/perm-b", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/perm-b/operations",
		map[string]any{"operations": []string{"write", "read"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/perm-b",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	// Scope "*" is active at both moments: the one unchanged path.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	// Everything else opens between the two moments.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-b/doc-2", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)

	body := diffView(h, "/subjects/user-1/access/diff?from=2026-02-01T00:00:00Z&to=2026-04-01T00:00:00Z")
	wantAdded := []any{
		wantItem("DIRECT_PERMISSION", nil, nil, "doc-read", []any{"read"}, "tenant-b/doc-2"),
		wantItem("ROLE", "viewer", "base", "doc-read", []any{"read"}, "tenant-a/*"),
		wantItem("ROLE", "viewer", "base", "perm-b", []any{"read", "write"}, "tenant-a/*"),
		wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "tenant-a/doc-1"),
	}
	if !reflect.DeepEqual(body["added"], wantAdded) {
		t.Fatalf("added = %v, want %v", body["added"], wantAdded)
	}
	if removed := body["removed"].([]any); len(removed) != 0 {
		t.Fatalf("removed = %v, want empty", removed)
	}
	wantUnchanged := []any{
		wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "*"),
	}
	if !reflect.DeepEqual(body["unchanged"], wantUnchanged) {
		t.Fatalf("unchanged = %v, want %v", body["unchanged"], wantUnchanged)
	}
}

func TestAccessDiffSubjectIdentifierWithSlash(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/"+enc("team-a/user-2"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/"+enc("team-a/user-2")+"/scopes",
		map[string]any{"permission": "doc-read", "scope": "*", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)

	body := diffView(h, "/subjects/"+enc("team-a/user-2")+"/access/diff?from=2026-02-01T00:00:00Z&to=2026-04-01T00:00:00Z")
	wantAdded := []any{wantItem("DIRECT_PERMISSION", nil, nil, "doc-read", []any{"read"}, "*")}
	if !reflect.DeepEqual(body["added"], wantAdded) {
		t.Fatalf("added = %v, want %v", body["added"], wantAdded)
	}
	if removed := body["removed"].([]any); len(removed) != 0 {
		t.Fatalf("removed = %v, want empty", removed)
	}
	if unchanged := body["unchanged"].([]any); len(unchanged) != 0 {
		t.Fatalf("unchanged = %v, want empty", unchanged)
	}
}

func TestAccessDiffErrorContract(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	expectError := func(target string, wantStatus int, wantType, wantField string) {
		t.Helper()
		recorder := h.request(http.MethodGet, target, nil)
		h.mustStatus(recorder, wantStatus)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		if errorObject["type"] != wantType {
			t.Fatalf("error type = %v, want %s", errorObject, wantType)
		}
		if wantField == "" {
			if _, ok := errorObject["field"]; ok {
				t.Fatalf("error unexpectedly carried field: %v", errorObject)
			}
		} else if errorObject["field"] != wantField {
			t.Fatalf("error field = %v, want %s", errorObject, wantField)
		}
	}

	// Missing or empty bounds are INVALID_REQUEST, from before to.
	expectError("/subjects/user-1/access/diff?to=2026-05-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "from")
	expectError("/subjects/user-1/access/diff?from=&to=2026-05-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "from")
	expectError("/subjects/user-1/access/diff?from=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "to")
	expectError("/subjects/user-1/access/diff?from=2026-02-01T00:00:00Z&to=", http.StatusBadRequest, "INVALID_REQUEST", "to")

	// Unparseable or unsupported times are INVALID_TIME, from outranking to.
	expectError("/subjects/user-1/access/diff?from=not-a-time&to=2026-05-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")
	expectError("/subjects/user-1/access/diff?from=2026-02-01T00:00:00Z&to=not-a-time", http.StatusBadRequest, "INVALID_TIME", "to")
	expectError("/subjects/user-1/access/diff?from=not-a-time&to=also-bad", http.StatusBadRequest, "INVALID_TIME", "from")
	expectError("/subjects/user-1/access/diff?from=10000-01-01T00:00:00Z&to=10001-01-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")

	// Time validation outranks the subject checks.
	expectError("/subjects/ghost/access/diff?from=not-a-time&to=2026-05-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")
	expectError("/subjects/bad%20id/access/diff?from=not-a-time&to=2026-05-01T00:00:00Z", http.StatusBadRequest, "INVALID_TIME", "from")

	// Range check outranks the subject checks.
	expectError("/subjects/ghost/access/diff?from=2026-05-01T00:00:00Z&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_RANGE", "")
	expectError("/subjects/bad%20id/access/diff?from=2026-05-01T00:00:00Z&to=2026-02-01T00:00:00Z", http.StatusBadRequest, "INVALID_RANGE", "")

	// After time validation, the subject grammar then existence apply.
	expectError("/subjects/bad%20id/access/diff?from=2026-02-01T00:00:00Z&to=2026-05-01T00:00:00Z", http.StatusBadRequest, "INVALID_REQUEST", "subject")
	expectError("/subjects/ghost/access/diff?from=2026-02-01T00:00:00Z&to=2026-05-01T00:00:00Z", http.StatusNotFound, "NOT_FOUND", "subject")
}
