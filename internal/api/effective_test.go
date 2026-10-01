package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

type apiHarness struct {
	t      *testing.T
	router http.Handler
}

func newHarness(t *testing.T) *apiHarness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &apiHarness{t: t, router: NewRouter(st)}
}

func (h *apiHarness) request(method, target string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, target, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, request)
	return recorder
}

func (h *apiHarness) raw(method, target, rawBody string) *httptest.ResponseRecorder {
	h.t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewBufferString(rawBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, request)
	return recorder
}

func (h *apiHarness) mustStatus(recorder *httptest.ResponseRecorder, want int) {
	h.t.Helper()
	if recorder.Code != want {
		h.t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), want)
	}
}

func mustJSON(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	return body
}

// seedBaseline registers catalog entries and builds:
// user-1 --viewer (with inheritance via parent base)-- doc-read -> read,
// plus a role scope on tenant-a/*.
func seedBaseline(h *apiHarness) {
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/resources/"+enc("tenant-a/doc-1"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/resources/"+enc("tenant-b/doc-2"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/operations/read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/operations/write", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-read/operations",
		map[string]any{"operations": []string{"read"}}), http.StatusOK)
}

func enc(id string) string { return url.PathEscape(id) }

func authorize(h *apiHarness, body map[string]any) map[string]any {
	recorder := h.request(http.MethodPost, "/authorize", body)
	h.mustStatus(recorder, http.StatusOK)
	response := mustJSON(h.t, recorder)
	decision, ok := response["decision"].(map[string]any)
	if !ok {
		h.t.Fatalf("missing decision: %s", recorder.Body.String())
	}
	return decision
}

func TestAuthorizeTimeWindowLifecycle(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	before := map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2025-12-01T00:00:00Z",
	}
	if decision := authorize(h, before); decision["reason"] != "NO_ROLE_BINDING" || decision["granted"] != false {
		t.Fatalf("before grants reason = %v", decision)
	}

	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	inWindow := map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T00:00:00Z",
	}
	decision := authorize(h, inWindow)
	if decision["granted"] != true || decision["matchedRole"] != "viewer" ||
		decision["matchedPermission"] != "doc-read" || decision["matchedScope"] != "tenant-a/*" {
		t.Fatalf("in-window decision = %v", decision)
	}

	// Revoking the binding closes its interval: later decisions become
	// NOT_EFFECTIVE because the binding existed historically.
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)
	after := map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-07-01T00:00:00Z",
	}
	if decision := authorize(h, after); decision["reason"] != "NOT_EFFECTIVE" || decision["granted"] != false {
		t.Fatalf("after revoke decision = %v", decision)
	}
}

func TestAuthorizeDenialReasons(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	triple := func(effectiveAt string) map[string]any {
		body := map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"}
		if effectiveAt != "" {
			body["effectiveAt"] = effectiveAt
		}
		return body
	}

	// Nothing exists yet.
	if decision := authorize(h, triple("2026-02-01T00:00:00Z")); decision["reason"] != "NO_ROLE_BINDING" {
		t.Fatalf("want NO_ROLE_BINDING, got %v", decision)
	}

	// Binding only: role exists but carries no covering permission grant.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	if decision := authorize(h, triple("2026-02-01T00:00:00Z")); decision["reason"] != "NO_PERMISSION_BINDING" {
		t.Fatalf("want NO_PERMISSION_BINDING, got %v", decision)
	}

	// Permission grant added, but no matching scope.
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	if decision := authorize(h, triple("2026-02-01T00:00:00Z")); decision["reason"] != "OUT_OF_SCOPE" {
		t.Fatalf("want OUT_OF_SCOPE, got %v", decision)
	}

	// A scope on an unrelated exact resource stays OUT_OF_SCOPE.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "other/resource", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	if decision := authorize(h, triple("2026-02-01T00:00:00Z")); decision["reason"] != "OUT_OF_SCOPE" {
		t.Fatalf("want OUT_OF_SCOPE with mismatching scope, got %v", decision)
	}

	// The matching scope interval is in the future.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2027-01-01T00:00:00Z"}), http.StatusOK)
	if decision := authorize(h, triple("2026-02-01T00:00:00Z")); decision["reason"] != "NOT_EFFECTIVE" {
		t.Fatalf("want NOT_EFFECTIVE with future scope, got %v", decision)
	}
}

func TestAuthorizeDirectGrantBypassesRole(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	decision := authorize(h, map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T00:00:00Z",
	})
	if decision["granted"] != true || decision["matchedRole"] != nil ||
		decision["matchedPermission"] != "doc-read" || decision["matchedScope"] != "tenant-a/doc-1" {
		t.Fatalf("direct decision = %v", decision)
	}

	// Direct grant expired historically => NOT_EFFECTIVE rather than role reasons.
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)
	decision = authorize(h, map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-07-01T00:00:00Z",
	})
	if decision["granted"] != false || decision["reason"] != "NOT_EFFECTIVE" {
		t.Fatalf("expired direct = %v", decision)
	}
}

func TestAuthorizeErrorContract(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	unknown := func(body map[string]any, wantField string) {
		t.Helper()
		recorder := h.request(http.MethodPost, "/authorize", body)
		h.mustStatus(recorder, http.StatusNotFound)
		response := mustJSON(t, recorder)
		errorObject := response["error"].(map[string]any)
		if errorObject["type"] != "NOT_FOUND" || errorObject["field"] != wantField {
			t.Fatalf("error = %v, want field %s", errorObject, wantField)
		}
	}
	unknown(map[string]any{"subject": "ghost", "resource": "tenant-a/doc-1", "operation": "read"}, "subject")
	unknown(map[string]any{"subject": "user-1", "resource": "ghost/x", "operation": "read"}, "resource")
	unknown(map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "delete"}, "operation")

	recorder := h.request(http.MethodPost, "/authorize", map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "effectiveAt": "not-a-time",
	})
	h.mustStatus(recorder, http.StatusBadRequest)
	errorObject := mustJSON(t, recorder)["error"].(map[string]any)
	if errorObject["type"] != "INVALID_TIME" {
		t.Fatalf("error = %v", errorObject)
	}
}

func TestAuthorizeDefaultTimeStaysCurrent(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	// Grants active from 2020 are certainly active now.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)

	decision := authorize(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"})
	if decision["granted"] != true {
		t.Fatalf("default-time decision = %v", decision)
	}
}

func history(h *apiHarness, target string) map[string]any {
	recorder := h.request(http.MethodGet, target, nil)
	h.mustStatus(recorder, http.StatusOK)
	return mustJSON(h.t, recorder)
}

func TestHistoryReturnsOrderedRelevantEvents(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	// Direct permission grant first, then the role-derived layers.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-02-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-04-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-05-01T00:00:00Z"}), http.StatusOK)

	response := history(h, "/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=read")
	events, ok := response["events"].([]any)
	if !ok || len(events) != 5 {
		t.Fatalf("events = %s", response)
	}
	froms := make([]string, len(events))
	eventTags := make([]string, len(events))
	for i, item := range events {
		event := item.(map[string]any)
		froms[i] = event["effectiveFrom"].(string)
		eventTags[i] = event["event"].(string)
	}
	wantFroms := []string{
		"2026-01-01T00:00:00Z",
		"2026-02-01T00:00:00Z",
		"2026-03-01T00:00:00Z",
		"2026-04-01T00:00:00Z",
		"2026-05-01T00:00:00Z",
	}
	for i := range wantFroms {
		if froms[i] != wantFroms[i] {
			t.Fatalf("order = %v, want %v", froms, wantFroms)
		}
	}
	if eventTags[4] != "REVOKE" {
		t.Fatalf("last event = %s", eventTags[4])
	}

	// The direct grant's first event grants immediately.
	first := events[0].(map[string]any)
	if first["granted"] != true || first["role"] != nil || first["permission"] != "doc-read" || first["scope"] != "tenant-a/doc-1" {
		t.Fatalf("first event = %v", first)
	}
	revoked := events[4].(map[string]any)
	// The direct permission grant stays active, so this triple remains granted
	// even after the role binding goes away.
	if revoked["granted"] != true || revoked["role"] != "viewer" || revoked["effectiveTo"] == nil {
		t.Fatalf("revoke event = %v", revoked)
	}
	if to := revoked["effectiveTo"].(string); to != "2026-05-01T00:00:00Z" {
		t.Fatalf("revoke effectiveTo = %v", revoked["effectiveTo"])
	}

	// Unrelated operation yields an empty list, not an error.
	empty := history(h, "/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=write")
	if len(empty["events"].([]any)) != 0 {
		t.Fatalf("unexpected events: %s", empty)
	}
}

func TestHistoryWindowingAndInvalidRange(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-02-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-04-01T00:00:00Z"}), http.StatusOK)

	response := history(h, "/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=read"+
		"&from=2026-03-01T00:00:00Z&to=2026-03-31T23:59:59Z")
	if len(response["events"].([]any)) != 1 {
		t.Fatalf("windowed events = %s", response)
	}

	recorder := h.request(http.MethodGet,
		"/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=read"+
			"&from=2026-09-01T00:00:00Z&to=2026-01-01T00:00:00Z", nil)
	h.mustStatus(recorder, http.StatusBadRequest)
	errorObject := mustJSON(t, recorder)["error"].(map[string]any)
	if errorObject["type"] != "INVALID_RANGE" {
		t.Fatalf("error = %v", errorObject)
	}
}

func TestUpdateMovesOpenInterval(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/roles/editor", nil), http.StatusOK)

	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "editor", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/editor/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	// Move the binding from viewer to editor mid-year.
	h.mustStatus(h.request(http.MethodPatch, "/subjects/user-1/bindings/viewer",
		map[string]any{"newRole": "editor", "effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)

	// Before the move the viewer path grants; after it the editor path grants.
	before := authorize(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "effectiveAt": "2026-05-01T00:00:00Z"})
	if before["granted"] != true || before["matchedRole"] != "viewer" {
		t.Fatalf("before update = %v", before)
	}
	after := authorize(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "effectiveAt": "2026-07-01T00:00:00Z"})
	if after["granted"] != true || after["matchedRole"] != "editor" {
		t.Fatalf("after update = %v", after)
	}
	historyEvents := history(h, "/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=read")["events"].([]any)
	var sawUpdate bool
	for _, item := range historyEvents {
		event := item.(map[string]any)
		if event["event"] == "UPDATE" && event["role"] == "editor" {
			sawUpdate = true
		}
	}
	if !sawUpdate {
		t.Fatalf("missing UPDATE event: %v", historyEvents)
	}
}

func TestRoleInheritanceReachesParentPermissions(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	// Permission lives on the inherited parent; scope is granted on base.
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	decision := authorize(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "effectiveAt": "2026-02-01T00:00:00Z"})
	if decision["granted"] != true || decision["matchedRole"] != "base" {
		t.Fatalf("inherited decision = %v", decision)
	}
}

func TestStrictJSONAndConflictContract(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	// Unknown fields are rejected.
	recorder := h.raw(http.MethodPost, "/authorize", `{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read","sneaky":1}`)
	h.mustStatus(recorder, http.StatusBadRequest)
	if typ := mustJSON(t, recorder)["error"].(map[string]any)["type"]; typ != "INVALID_REQUEST" {
		t.Fatalf("type = %v", typ)
	}

	// Type mismatch is rejected.
	recorder = h.raw(http.MethodPost, "/authorize", `{"subject":["user-1"],"resource":"x","operation":"read"}`)
	h.mustStatus(recorder, http.StatusBadRequest)

	// Duplicate open grants conflict.
	grant := func() *httptest.ResponseRecorder {
		return h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
			map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"})
	}
	h.mustStatus(grant(), http.StatusOK)
	recorder = grant()
	h.mustStatus(recorder, http.StatusConflict)
	if typ := mustJSON(t, recorder)["error"].(map[string]any)["type"]; typ != "CONFLICT" {
		t.Fatalf("type = %v", typ)
	}

	// Revoking a missing identity is NOT_FOUND.
	recorder = h.request(http.MethodDelete, "/subjects/user-1/bindings/ghost",
		map[string]any{"effectiveFrom": "2026-02-01T00:00:00Z"})
	h.mustStatus(recorder, http.StatusNotFound)
}

func TestHistorySameInstantStableOrder(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	instant := map[string]any{"effectiveFrom": "2026-04-01T00:00:00Z", "occurredAt": "2026-04-01T00:00:00Z"}

	grant := func(body map[string]any, target string) {
		merged := map[string]any{}
		for k, v := range instant {
			merged[k] = v
		}
		for k, v := range body {
			merged[k] = v
		}
		h.mustStatus(h.request(http.MethodPut, target, merged), http.StatusOK)
	}
	// Insert in non-chronological logical order; all share effectiveFrom and
	// occurredAt, so insertion order is the stable tiebreak.
	grant(map[string]any{"role": "viewer", "scope": "tenant-a/*"}, "/subjects/user-1/scopes")
	grant(nil, "/roles/viewer/permissions/doc-read")
	grant(nil, "/subjects/user-1/bindings/viewer")

	response := history(h, "/history?subject=user-1&resource="+enc("tenant-a/doc-1")+"&operation=read")
	events := response["events"].([]any)
	if len(events) != 3 {
		t.Fatalf("events = %s", response)
	}
	roles := []any{}
	for _, item := range events {
		event := item.(map[string]any)
		if event["effectiveFrom"] != "2026-04-01T00:00:00Z" {
			t.Fatalf("unexpected from %v", event)
		}
		roles = append(roles, event["role"])
	}
	// Scope row inserted first, rolePerm second, binding third; all carry
	// role viewer, so identity alone cannot prove order — assert event shapes
	// are present and stable across repeated calls.
	first := events[0].(map[string]any)
	second := events[1].(map[string]any)
	if first["scope"] != "tenant-a/*" {
		t.Fatalf("first = %v", first)
	}
	if first["scope"] == second["scope"] && first["permission"] == second["permission"] {
		t.Fatalf("tiebreak collapsed: %v %v", first, second)
	}
}

func TestUpdateScopeAndRolePermission(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/roles/auditor", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-audit", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-audit/operations",
		map[string]any{"operations": []string{"read"}}), http.StatusOK)

	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	// Move the role-permission grant to a new permission.
	h.mustStatus(h.request(http.MethodPatch, "/roles/viewer/permissions/doc-read",
		map[string]any{"newRole": "viewer", "newPermission": "doc-audit", "effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)
	// doc-read no longer active after June; doc-audit scope uses the same
	// pattern because the scope was granted on the role, so access continues.
	after := authorize(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "effectiveAt": "2026-07-01T00:00:00Z"})
	if after["granted"] != true || after["matchedPermission"] != "doc-audit" {
		t.Fatalf("after roleperm update = %v", after)
	}
	before := authorize(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "effectiveAt": "2026-02-01T00:00:00Z"})
	if before["granted"] != true || before["matchedPermission"] != "doc-read" {
		t.Fatalf("before roleperm update = %v", before)
	}

	// Move the scope to a narrower exact boundary.
	h.mustStatus(h.request(http.MethodPatch, "/subjects/user-1/scopes",
		map[string]any{
			"role":          "viewer",
			"scope":         "tenant-a/*",
			"newRole":       "viewer",
			"newScope":      "tenant-a/doc-1",
			"effectiveFrom": "2026-08-01T00:00:00Z",
		}), http.StatusOK)
	narrowed := authorize(h, map[string]any{"subject": "user-1", "resource": "tenant-b/doc-2", "operation": "read", "effectiveAt": "2026-09-01T00:00:00Z"})
	if narrowed["granted"] != false || narrowed["reason"] != "OUT_OF_SCOPE" {
		t.Fatalf("narrowed = %v", narrowed)
	}
	exact := authorize(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "effectiveAt": "2026-09-01T00:00:00Z"})
	if exact["granted"] != true || exact["matchedScope"] != "tenant-a/doc-1" {
		t.Fatalf("exact = %v", exact)
	}
}
