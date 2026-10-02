package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func accessList(h *apiHarness, target string) []any {
	h.t.Helper()
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	response := mustJSON(h.t, recorder)
	items, ok := response["access"].([]any)
	if !ok {
		h.t.Fatalf("missing access list: %s", recorder.Body.String())
	}
	return items
}

func wantItem(source string, boundRole, role any, permission string, operations []any, scope string) map[string]any {
	return map[string]any{
		"source":     source,
		"boundRole":  boundRole,
		"role":       role,
		"permission": permission,
		"operations": operations,
		"scope":      scope,
	}
}

// grantAt issues a PUT with a fixed effectiveFrom, merging any extra body.
func grantAt(h *apiHarness, target string, body map[string]any) {
	h.t.Helper()
	merged := map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}
	for key, value := range body {
		merged[key] = value
	}
	h.mustStatus(h.request(http.MethodPut, target, merged), http.StatusOK)
}

func TestAccessListsRoleAndDirectPaths(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/editor", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/perm-b", nil), http.StatusOK)
	// Operations are stored out of order; the listing must sort them.
	h.mustStatus(h.request(http.MethodPut, "/permissions/perm-b/operations",
		map[string]any{"operations": []string{"write", "read"}}), http.StatusOK)

	grantAt(h, "/subjects/user-1/bindings/viewer", nil)
	grantAt(h, "/subjects/user-1/bindings/editor", nil)
	grantAt(h, "/roles/base/permissions/doc-read", nil)
	grantAt(h, "/roles/base/permissions/perm-b", nil)
	grantAt(h, "/roles/editor/permissions/doc-read", nil)
	grantAt(h, "/roles/viewer/permissions/doc-read", nil)
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "base", "scope": "tenant-a/*"})
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "base", "scope": "*"})
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "editor", "scope": "*"})
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "viewer", "scope": "tenant-a/doc-1"})
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"permission": "doc-read", "scope": "tenant-b/doc-2"})

	items := accessList(h, "/subjects/user-1/access?effectiveAt=2026-02-01T00:00:00Z")
	want := []any{
		wantItem("DIRECT_PERMISSION", nil, nil, "doc-read", []any{"read"}, "tenant-b/doc-2"),
		wantItem("ROLE", "editor", "editor", "doc-read", []any{"read"}, "*"),
		wantItem("ROLE", "viewer", "base", "doc-read", []any{"read"}, "*"),
		wantItem("ROLE", "viewer", "base", "doc-read", []any{"read"}, "tenant-a/*"),
		wantItem("ROLE", "viewer", "base", "perm-b", []any{"read", "write"}, "*"),
		wantItem("ROLE", "viewer", "base", "perm-b", []any{"read", "write"}, "tenant-a/*"),
		wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "tenant-a/doc-1"),
	}
	if !reflect.DeepEqual(items, want) {
		got, _ := json.Marshal(items)
		t.Fatalf("access = %s", got)
	}

	// Before every interval opened there is no effective path.
	if items := accessList(h, "/subjects/user-1/access?effectiveAt=2025-12-01T00:00:00Z"); len(items) != 0 {
		t.Fatalf("pre-grant access = %v", items)
	}
}

func TestAccessRequiresAllThreeLayers(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-02-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)

	for _, when := range []string{"2026-01-15T00:00:00Z", "2026-02-15T00:00:00Z"} {
		if items := accessList(h, "/subjects/user-1/access?effectiveAt="+when); len(items) != 0 {
			t.Fatalf("access at %s = %v, want empty", when, items)
		}
	}
	items := accessList(h, "/subjects/user-1/access?effectiveAt=2026-03-15T00:00:00Z")
	want := []any{wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "tenant-a/*")}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("access = %v, want %v", items, want)
	}
}

func TestAccessEmptyListShape(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	recorder := h.request(http.MethodGet, "/subjects/user-1/access?effectiveAt=2026-02-01T00:00:00Z", nil)
	h.mustStatus(recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"access":[]`) {
		t.Fatalf("empty body = %s", recorder.Body.String())
	}
}

func TestAccessDeduplicatesOverlappingVersions(t *testing.T) {
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

	items := accessList(h, "/subjects/user-1/access?effectiveAt=2026-04-01T00:00:00Z")
	want := []any{wantItem("ROLE", "viewer", "viewer", "doc-read", []any{"read"}, "tenant-a/*")}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("access = %v, want %v", items, want)
	}
}

func TestAccessDefaultsToCurrentTime(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)

	items := accessList(h, "/subjects/user-1/access")
	if len(items) != 1 {
		t.Fatalf("access = %v, want one item", items)
	}
}

func TestAccessSubjectIdentifierWithSlash(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/"+enc("team-a/user-2"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/"+enc("team-a/user-2")+"/scopes",
		map[string]any{"permission": "doc-read", "scope": "*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	items := accessList(h, "/subjects/"+enc("team-a/user-2")+"/access?effectiveAt=2026-02-01T00:00:00Z")
	want := []any{wantItem("DIRECT_PERMISSION", nil, nil, "doc-read", []any{"read"}, "*")}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("access = %v, want %v", items, want)
	}
}

func TestAccessErrorContract(t *testing.T) {
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

	expectError("/subjects/ghost/access", http.StatusNotFound, "NOT_FOUND", "subject")
	expectError("/subjects/bad%20id/access", http.StatusBadRequest, "INVALID_REQUEST", "subject")
	expectError("/subjects/user-1/access?effectiveAt=not-a-time", http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	// A malformed effectiveAt is the sole failure even when the subject is
	// unknown as well.
	expectError("/subjects/ghost/access?effectiveAt=not-a-time", http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
}
