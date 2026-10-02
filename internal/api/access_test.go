package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func accessList(h *apiHarness, target string) []any {
	h.t.Helper()
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	response := mustJSON(h.t, recorder)
	entries, ok := response["access"].([]any)
	if !ok {
		h.t.Fatalf("missing access array: %s", recorder.Body.String())
	}
	return entries
}

// accessTuple renders one entry as an ordered comparison slice, with null
// roles rendered as the fixed "<null>" marker.
func accessTuple(t *testing.T, raw any) []string {
	t.Helper()
	entry, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("entry is not an object: %v", raw)
	}
	roleField := func(key string) string {
		if value, ok := entry[key].(string); ok {
			return value
		}
		if entry[key] != nil {
			t.Fatalf("%s is not null/string: %v", key, entry[key])
		}
		return "<null>"
	}
	operations := []string{}
	for _, value := range entry["operations"].([]any) {
		operations = append(operations, value.(string))
	}
	ops, err := json.Marshal(operations)
	if err != nil {
		t.Fatalf("marshal ops: %v", err)
	}
	return []string{
		entry["source"].(string),
		roleField("boundRole"),
		roleField("role"),
		entry["permission"].(string),
		string(ops),
		entry["scope"].(string),
	}
}

func seedAccessGraph(h *apiHarness) {
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/resources/"+enc("tenant-a/doc-1"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/resources/"+enc("tenant-a/doc-2"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/resources/"+enc("tenant-b/doc-9"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/operations/read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/operations/write", nil), http.StatusOK)
	for _, role := range []string{"base", "viewer", "lead", "mgr", "senior"} {
		h.mustStatus(h.request(http.MethodPut, "/roles/"+role, nil), http.StatusOK)
	}
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-write", nil), http.StatusOK)
	// Operations are configured out of order to prove lexicographic output.
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read/operations",
		map[string]any{"operations": []string{"write", "read"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-write/operations",
		map[string]any{"operations": []string{"write"}}), http.StatusOK)

	// viewer -> base ; senior -> viewer ; mgr -> {lead, viewer} -> base (diamond).
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/senior/parents",
		map[string]any{"parents": []string{"viewer"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/lead/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/mgr/parents",
		map[string]any{"parents": []string{"lead", "viewer"}}), http.StatusOK)

	from := map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer", from), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/senior", from), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/mgr", from), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/doc-read", from), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-write", from), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "senior", "scope": "tenant-b/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	// Direct permission grant skips the role layer entirely.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-2", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
}

func TestSubjectAccessEffectivePaths(t *testing.T) {
	h := newHarness(t)
	seedAccessGraph(h)

	entries := accessList(h, "/subjects/user-1/access?effectiveAt=2026-02-01T00:00:00Z")
	got := make([][]string, 0, len(entries))
	for _, raw := range entries {
		got = append(got, accessTuple(t, raw))
	}
	want := [][]string{
		{"DIRECT_PERMISSION", "<null>", "<null>", "doc-read", `["read","write"]`, "tenant-a/doc-2"},
		{"ROLE", "mgr", "base", "doc-read", `["read","write"]`, "tenant-a/*"},
		{"ROLE", "mgr", "viewer", "doc-write", `["write"]`, "tenant-a/doc-1"},
		{"ROLE", "senior", "base", "doc-read", `["read","write"]`, "tenant-a/*"},
		{"ROLE", "senior", "viewer", "doc-write", `["write"]`, "tenant-a/doc-1"},
		{"ROLE", "viewer", "base", "doc-read", `["read","write"]`, "tenant-a/*"},
		{"ROLE", "viewer", "viewer", "doc-write", `["write"]`, "tenant-a/doc-1"},
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for i := range want {
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Fatalf("entry %d field %d = %q, want %q\nall = %v", i, j, got[i][j], want[i][j], got)
			}
		}
	}
}

func TestSubjectAccessThreeLayerWindows(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	bind := map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}
	permGrant := map[string]any{"effectiveFrom": "2026-03-01T00:00:00Z"}
	scopeGrant := map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer", bind), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read", permGrant), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes", scopeGrant), http.StatusOK)

	if entries := accessList(h, "/subjects/user-1/access?effectiveAt=2026-02-01T00:00:00Z"); len(entries) != 0 {
		t.Fatalf("before role/permission interval: %v", entries)
	}
	entries := accessList(h, "/subjects/user-1/access?effectiveAt=2026-04-01T00:00:00Z")
	if len(entries) != 1 {
		t.Fatalf("within all three intervals: %v", entries)
	}
	tuple := accessTuple(t, entries[0])
	want := []string{"ROLE", "viewer", "viewer", "doc-read", `["read"]`, "tenant-a/*"}
	for i := range want {
		if tuple[i] != want[i] {
			t.Fatalf("tuple = %v, want %v", tuple, want)
		}
	}

	// Closing the scope interval removes the path; an empty list is not an error.
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)
	if entries := accessList(h, "/subjects/user-1/access?effectiveAt=2026-07-01T00:00:00Z"); len(entries) != 0 {
		t.Fatalf("after scope revoke: %v", entries)
	}
}

func TestSubjectAccessEmptyAndDefaultTime(t *testing.T) {
	h := newHarness(t)
	h.mustStatus(h.request(http.MethodPut, "/subjects/empty-1", nil), http.StatusOK)

	recorder := h.request(http.MethodGet, "/subjects/empty-1/access", nil)
	h.mustStatus(recorder, http.StatusOK)
	if body := recorder.Body.String(); body != `{"access":[]}` {
		t.Fatalf("empty body = %s", body)
	}

	// An open interval granted now must show up when effectiveAt is omitted.
	h.mustStatus(h.request(http.MethodPut, "/operations/read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read/operations",
		map[string]any{"operations": []string{"read"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/empty-1/bindings/viewer", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/empty-1/scopes",
		map[string]any{"role": "viewer", "scope": "*"}), http.StatusOK)
	if entries := accessList(h, "/subjects/empty-1/access"); len(entries) != 1 {
		t.Fatalf("current-time access = %v", entries)
	}
}

func TestSubjectAccessEncodedSlashIdentifier(t *testing.T) {
	h := newHarness(t)
	subject := "tenant-a/sub-1"
	encoded := url.PathEscape(subject)
	h.mustStatus(h.request(http.MethodPut, "/subjects/"+encoded, nil), http.StatusOK)
	recorder := h.request(http.MethodGet, "/subjects/"+encoded+"/access", nil)
	h.mustStatus(recorder, http.StatusOK)
	if body := recorder.Body.String(); body != `{"access":[]}` {
		t.Fatalf("encoded slash body = %s", body)
	}
}

func TestSubjectAccessErrors(t *testing.T) {
	h := newHarness(t)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1", nil), http.StatusOK)

	cases := []struct {
		name   string
		target string
		typ    string
		field  string
	}{
		{"missing subject", "/subjects/ghost/access", "NOT_FOUND", "subject"},
		{"illegal identifier", "/subjects/bad%20id/access", "INVALID_REQUEST", "subject"},
		{"bad time", "/subjects/user-1/access?effectiveAt=not-a-time", "INVALID_TIME", "effectiveAt"},
		{"out of range time", "/subjects/user-1/access?effectiveAt=10000-01-01T00:00:00Z", "INVALID_TIME", "effectiveAt"},
		// An illegal time is reported as INVALID_TIME even when the subject
		// itself does not exist.
		{"bad time wins over missing subject", "/subjects/ghost/access?effectiveAt=not-a-time", "INVALID_TIME", "effectiveAt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := h.request(http.MethodGet, tc.target, nil)
			if recorder.Code != http.StatusBadRequest && tc.typ != "NOT_FOUND" {
				t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
			}
			if tc.typ == "NOT_FOUND" && recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
			}
			errObj := mustJSON(t, recorder)["error"].(map[string]any)
			if errObj["type"] != tc.typ || errObj["field"] != tc.field {
				t.Fatalf("error = %v, want type %s field %s", errObj, tc.typ, tc.field)
			}
		})
	}
}

func TestSubjectAccessWritesNoHistory(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	historyTarget := "/history?subject=user-1&resource=" + enc("tenant-a/doc-1") + "&operation=read"
	before := history(h, historyTarget)["events"].([]any)
	accessList(h, "/subjects/user-1/access?effectiveAt=2026-02-01T00:00:00Z")
	accessList(h, "/subjects/user-1/access?effectiveAt=2026-03-01T00:00:00Z")
	after := history(h, historyTarget)["events"].([]any)
	if len(before) != len(after) {
		t.Fatalf("history changed: before %d after %d", len(before), len(after))
	}
}
