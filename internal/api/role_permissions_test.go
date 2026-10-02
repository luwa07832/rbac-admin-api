package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func rolePermissions(h *apiHarness, target string) map[string]any {
	h.t.Helper()
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	response := mustJSON(h.t, recorder)
	return response
}

func wantRolePerm(role, permission string, operations []any, source string) map[string]any {
	return map[string]any{
		"role":       role,
		"permission": permission,
		"operations": operations,
		"source":     source,
	}
}

// seedRoleGraph builds viewer -> {mid, base}, mid -> base, plus an
// unrelated "other" role whose grants must never leak into viewer.
func seedRoleGraph(h *apiHarness) {
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/mid", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/other", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/operations/read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/operations/write", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"mid", "base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/mid/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/perm-b", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read/operations",
		map[string]any{"operations": []string{"read"}}), http.StatusOK)
	// Operations are stored out of order; the listing must sort and dedupe.
	h.mustStatus(h.request(http.MethodPut, "/permissions/perm-b/operations",
		map[string]any{"operations": []string{"write", "read"}}), http.StatusOK)
}

func TestRolePermissionsExpandsInheritance(t *testing.T) {
	h := newHarness(t)
	seedRoleGraph(h)
	grantAt(h, "/roles/viewer/permissions/doc-read", nil)
	grantAt(h, "/roles/mid/permissions/perm-b", nil)
	grantAt(h, "/roles/base/permissions/doc-read", nil)
	grantAt(h, "/roles/other/permissions/doc-read", nil)

	view := rolePermissions(h, "/roles/viewer/permissions?effectiveAt=2026-02-01T00:00:00Z")
	if view["effectiveAt"] != "2026-02-01T00:00:00Z" || view["role"] != "viewer" {
		t.Fatalf("view header = %v", view)
	}
	if got := view["parents"]; !reflect.DeepEqual(got, []any{"base", "mid"}) {
		t.Fatalf("parents = %v", got)
	}
	if got := view["inheritedRoles"]; !reflect.DeepEqual(got, []any{"base", "mid"}) {
		t.Fatalf("inheritedRoles = %v", got)
	}
	want := []any{
		wantRolePerm("base", "doc-read", []any{"read"}, "INHERITED"),
		wantRolePerm("mid", "perm-b", []any{"read", "write"}, "INHERITED"),
		wantRolePerm("viewer", "doc-read", []any{"read"}, "DIRECT"),
	}
	if got := view["permissions"]; !reflect.DeepEqual(got, want) {
		raw, _ := json.Marshal(got)
		t.Fatalf("permissions = %s", raw)
	}
}

func TestRolePermissionsOnlyGrantsAreTimeFiltered(t *testing.T) {
	h := newHarness(t)
	seedRoleGraph(h)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-02-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodDelete, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-04-01T00:00:00Z"}), http.StatusOK)

	// Before the grant there is no permission, but the current inheritance
	// graph is still expanded in full.
	before := rolePermissions(h, "/roles/viewer/permissions?effectiveAt=2026-01-01T00:00:00Z")
	if got := before["permissions"]; !reflect.DeepEqual(got, []any{}) {
		t.Fatalf("before permissions = %v", got)
	}
	if got := before["inheritedRoles"]; !reflect.DeepEqual(got, []any{"base", "mid"}) {
		t.Fatalf("before inheritedRoles = %v", got)
	}

	active := rolePermissions(h, "/roles/viewer/permissions?effectiveAt=2026-03-01T00:00:00Z")
	want := []any{wantRolePerm("viewer", "doc-read", []any{"read"}, "DIRECT")}
	if got := active["permissions"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("active permissions = %v", got)
	}

	after := rolePermissions(h, "/roles/viewer/permissions?effectiveAt=2026-05-01T00:00:00Z")
	if got := after["permissions"]; !reflect.DeepEqual(got, []any{}) {
		t.Fatalf("after permissions = %v", got)
	}
}

func TestRolePermissionsEmptyArraysAndDefaultTime(t *testing.T) {
	h := newHarness(t)
	seedRoleGraph(h)
	recorder := h.request(http.MethodGet, "/roles/viewer/permissions?effectiveAt=2026-02-01T00:00:00Z", nil)
	h.mustStatus(recorder, http.StatusOK)
	body := recorder.Body.String()
	for _, fragment := range []string{`"parents":["base","mid"]`, `"inheritedRoles":["base","mid"]`, `"permissions":[]`} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("body %q missing %s", body, fragment)
		}
	}

	// A leaf role with no parents renders empty arrays.
	leaf := rolePermissions(h, "/roles/other/permissions?effectiveAt=2026-02-01T00:00:00Z")
	if got := leaf["parents"]; !reflect.DeepEqual(got, []any{}) {
		t.Fatalf("leaf parents = %v", got)
	}
	if got := leaf["inheritedRoles"]; !reflect.DeepEqual(got, []any{}) {
		t.Fatalf("leaf inheritedRoles = %v", got)
	}

	// Without effectiveAt the query evaluates at the current moment.
	h.mustStatus(h.request(http.MethodPut, "/roles/other/permissions/doc-read",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	current := rolePermissions(h, "/roles/other/permissions")
	want := []any{wantRolePerm("other", "doc-read", []any{"read"}, "DIRECT")}
	if got := current["permissions"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("current permissions = %v", got)
	}
}

func TestRolePermissionsIdentifierWithSlash(t *testing.T) {
	h := newHarness(t)
	h.mustStatus(h.request(http.MethodPut, "/operations/read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/"+enc("team-a/admin"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read/operations",
		map[string]any{"operations": []string{"read"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/"+enc("team-a/admin")+"/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	view := rolePermissions(h, "/roles/"+enc("team-a/admin")+"/permissions?effectiveAt=2026-02-01T00:00:00Z")
	if view["role"] != "team-a/admin" {
		t.Fatalf("role = %v", view["role"])
	}
	want := []any{wantRolePerm("team-a/admin", "doc-read", []any{"read"}, "DIRECT")}
	if got := view["permissions"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("permissions = %v", got)
	}
}

func TestRolePermissionsErrorContract(t *testing.T) {
	h := newHarness(t)
	seedRoleGraph(h)

	expectError := func(target string, wantStatus int, wantType, wantField string) {
		t.Helper()
		recorder := h.request(http.MethodGet, target, nil)
		h.mustStatus(recorder, wantStatus)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		if errorObject["type"] != wantType || errorObject["field"] != wantField {
			t.Fatalf("error = %v, want %s/%s", errorObject, wantType, wantField)
		}
	}

	expectError("/roles/ghost/permissions", http.StatusNotFound, "NOT_FOUND", "role")
	expectError("/roles/bad%20id/permissions", http.StatusBadRequest, "INVALID_REQUEST", "role")
	expectError("/roles/viewer/permissions?effectiveAt=not-a-time", http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	// A malformed effectiveAt is the sole failure even when the role is
	// unknown as well.
	expectError("/roles/ghost/permissions?effectiveAt=not-a-time", http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
}
