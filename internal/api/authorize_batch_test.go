package api

import (
	"net/http"
	"reflect"
	"testing"
)

func batchAuthorize(h *apiHarness, body any) []any {
	h.t.Helper()
	recorder := h.request(http.MethodPost, "/authorize/batch", body)
	h.mustStatus(recorder, http.StatusOK)
	response := mustJSON(h.t, recorder)
	decisions, ok := response["decisions"].([]any)
	if !ok {
		h.t.Fatalf("missing decisions: %s", recorder.Body.String())
	}
	return decisions
}

func batchError(t *testing.T, h *apiHarness, body any) (int, map[string]any) {
	t.Helper()
	recorder := h.request(http.MethodPost, "/authorize/batch", body)
	response := mustJSON(t, recorder)
	errorObject, ok := response["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error: %s", recorder.Body.String())
	}
	if _, exists := response["decisions"]; exists {
		t.Fatalf("error response contains decisions: %s", recorder.Body.String())
	}
	return recorder.Code, errorObject
}

func batchRawError(t *testing.T, h *apiHarness, rawBody string) (int, map[string]any) {
	t.Helper()
	recorder := h.raw(http.MethodPost, "/authorize/batch", rawBody)
	response := mustJSON(t, recorder)
	errorObject, ok := response["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error: %s", recorder.Body.String())
	}
	if _, exists := response["decisions"]; exists {
		t.Fatalf("error response contains decisions: %s", recorder.Body.String())
	}
	return recorder.Code, errorObject
}

func seedBatchAuthorizations(h *apiHarness) {
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-3", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/resources/"+enc("tenant-a/report"), nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-3/bindings/viewer",
		map[string]any{"effectiveFrom": "2027-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
}

func TestAuthorizeBatchReturnsOrderedDecisionsAndMatchesSingle(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedBatchAuthorizations(h)

	queries := []any{
		map[string]any{"subject": "user-1", "resource": "tenant-b/doc-2", "operation": "read"},
		map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
		map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
		map[string]any{"subject": "user-1", "resource": "tenant-a/report", "operation": "read"},
		map[string]any{"subject": "user-2", "resource": "tenant-a/report", "operation": "read"},
		map[string]any{"subject": "user-1", "resource": "tenant-a/report", "operation": "write"},
		map[string]any{"subject": "user-3", "resource": "tenant-a/report", "operation": "read"},
	}
	body := map[string]any{"effectiveAt": "2026-02-01T00:00:00Z", "queries": queries}
	decisions := batchAuthorize(h, body)

	want := []map[string]any{
		{"subject": "user-1", "resource": "tenant-b/doc-2", "operation": "read", "granted": false, "reason": "OUT_OF_SCOPE"},
		{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "granted": true, "matchedRole": nil, "matchedPermission": "doc-read", "matchedScope": "tenant-a/doc-1"},
		{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "granted": true, "matchedRole": nil, "matchedPermission": "doc-read", "matchedScope": "tenant-a/doc-1"},
		{"subject": "user-1", "resource": "tenant-a/report", "operation": "read", "granted": true, "matchedRole": "base", "matchedPermission": "doc-read", "matchedScope": "tenant-a/*"},
		{"subject": "user-2", "resource": "tenant-a/report", "operation": "read", "granted": false, "reason": "NO_ROLE_BINDING"},
		{"subject": "user-1", "resource": "tenant-a/report", "operation": "write", "granted": false, "reason": "NO_PERMISSION_BINDING"},
		{"subject": "user-3", "resource": "tenant-a/report", "operation": "read", "granted": false, "reason": "NOT_EFFECTIVE"},
	}
	if len(decisions) != len(want) {
		t.Fatalf("len(decisions) = %d, want %d: %v", len(decisions), len(want), decisions)
	}
	for index := range want {
		got := decisions[index].(map[string]any)
		if !reflect.DeepEqual(got, want[index]) {
			t.Fatalf("decision %d = %v, want %v", index, got, want[index])
		}

		singleBody := map[string]any{
			"subject":     queries[index].(map[string]any)["subject"],
			"resource":    queries[index].(map[string]any)["resource"],
			"operation":   queries[index].(map[string]any)["operation"],
			"effectiveAt": "2026-02-01T00:00:00Z",
		}
		single := authorize(h, singleBody)
		for key, value := range single {
			if got[key] != value {
				t.Fatalf("batch decision %d field %s = %v, single = %v", index, key, got[key], value)
			}
		}
	}
}

func TestAuthorizeBatchDefaultEffectiveAt(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)

	decisions := batchAuthorize(h, map[string]any{"queries": []any{
		map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
	}})
	decision := decisions[0].(map[string]any)
	if decision["granted"] != true {
		t.Fatalf("default-time decision = %v", decision)
	}
}

func TestAuthorizeBatchUsesSharedHalfOpenInterval(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedBatchAuthorizations(h)
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)

	query := []any{map[string]any{"subject": "user-1", "resource": "tenant-a/report", "operation": "read"}}
	before := batchAuthorize(h, map[string]any{"effectiveAt": "2026-05-31T23:59:59Z", "queries": query})[0].(map[string]any)
	if before["granted"] != true || before["matchedRole"] != "base" {
		t.Fatalf("before interval end = %v", before)
	}
	atEnd := batchAuthorize(h, map[string]any{"effectiveAt": "2026-06-01T00:00:00Z", "queries": query})[0].(map[string]any)
	if atEnd["granted"] != false || atEnd["reason"] != "NOT_EFFECTIVE" {
		t.Fatalf("at interval end = %v, want NOT_EFFECTIVE", atEnd)
	}
}

func TestAuthorizeBatchSizeLimit(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	query := map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"}

	hundred := make([]any, 100)
	for index := range hundred {
		hundred[index] = query
	}
	if decisions := batchAuthorize(h, map[string]any{"queries": hundred}); len(decisions) != 100 {
		t.Fatalf("len(decisions) = %d, want 100", len(decisions))
	}

	hundredOne := make([]any, 101)
	for index := range hundredOne {
		hundredOne[index] = query
	}
	status, errorObject := batchError(t, h, map[string]any{"queries": hundredOne})
	if status != http.StatusBadRequest || errorObject["type"] != "INVALID_REQUEST" || errorObject["field"] != "queries" {
		t.Fatalf("101-item error = %d %v", status, errorObject)
	}
}

func TestAuthorizeBatchRequestStructureErrors(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	validQuery := map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"}

	cases := []struct {
		name      string
		body      any
		wantType  string
		wantField string
	}{
		{"missing queries", map[string]any{}, "INVALID_REQUEST", "queries"},
		{"empty queries", map[string]any{"queries": []any{}}, "INVALID_REQUEST", "queries"},
		{"queries is object", map[string]any{"queries": map[string]any{}}, "INVALID_REQUEST", "queries"},
		{"top unknown field", map[string]any{"queries": []any{validQuery}, "extra": true}, "INVALID_REQUEST", "extra"},
		{"missing subject", map[string]any{"queries": []any{map[string]any{"resource": "tenant-a/doc-1", "operation": "read"}}}, "INVALID_REQUEST", "queries[0].subject"},
		{"missing resource", map[string]any{"queries": []any{map[string]any{"subject": "user-1", "operation": "read"}}}, "INVALID_REQUEST", "queries[0].resource"},
		{"missing operation", map[string]any{"queries": []any{map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1"}}}, "INVALID_REQUEST", "queries[0].operation"},
		{"item unknown field", map[string]any{"queries": []any{map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read", "extra": true}}}, "INVALID_REQUEST", "queries[0].extra"},
		{"invalid subject", map[string]any{"queries": []any{map[string]any{"subject": "bad id", "resource": "tenant-a/doc-1", "operation": "read"}}}, "INVALID_REQUEST", "queries[0].subject"},
		{"invalid resource", map[string]any{"queries": []any{map[string]any{"subject": "user-1", "resource": "bad id", "operation": "read"}}}, "INVALID_REQUEST", "queries[0].resource"},
		{"invalid operation", map[string]any{"queries": []any{map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "bad id"}}}, "INVALID_REQUEST", "queries[0].operation"},
		{"later item first", map[string]any{"queries": []any{validQuery, map[string]any{"subject": "ghost", "resource": "tenant-a/doc-1", "operation": "read"}}}, "NOT_FOUND", "queries[1].subject"},
		{"unknown subject", map[string]any{"queries": []any{map[string]any{"subject": "ghost", "resource": "tenant-a/doc-1", "operation": "read"}}}, "NOT_FOUND", "queries[0].subject"},
		{"unknown resource", map[string]any{"queries": []any{map[string]any{"subject": "user-1", "resource": "ghost/x", "operation": "read"}}}, "NOT_FOUND", "queries[0].resource"},
		{"unknown operation", map[string]any{"queries": []any{map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "delete"}}}, "NOT_FOUND", "queries[0].operation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, errorObject := batchError(t, h, tc.body)
			wantStatus := http.StatusBadRequest
			if tc.wantType == "NOT_FOUND" {
				wantStatus = http.StatusNotFound
			}
			if status != wantStatus || errorObject["type"] != tc.wantType || errorObject["field"] != tc.wantField {
				t.Fatalf("error = %d %v, want %d %s/%s", status, errorObject, wantStatus, tc.wantType, tc.wantField)
			}
		})
	}
}

func TestAuthorizeBatchRawStructureErrors(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name      string
		raw       string
		wantType  string
		wantField string
	}{
		{"null queries", `{"queries":null}`, "INVALID_REQUEST", "queries"},
		{"null item", `{"queries":[null]}`, "INVALID_REQUEST", "queries[0]"},
		{"array item", `{"queries":[["user-1"]]}`, "INVALID_REQUEST", "queries[0]"},
		{"number subject", `{"queries":[{"subject":1,"resource":"tenant-a/doc-1","operation":"read"}]}`, "INVALID_REQUEST", "queries[0].subject"},
		{"number time", `{"effectiveAt":1,"queries":[]}`, "INVALID_TIME", "effectiveAt"},
		{"null time", `{"effectiveAt":null,"queries":[]}`, "INVALID_TIME", "effectiveAt"},
		{"empty time", `{"effectiveAt":"","queries":[]}`, "INVALID_TIME", "effectiveAt"},
		{"invalid time before item", `{"effectiveAt":"nope","queries":[{"resource":"tenant-a/doc-1","operation":"read"}]}`, "INVALID_TIME", "effectiveAt"},
		{"invalid time before item type", `{"effectiveAt":"nope","queries":[{"subject":1,"resource":"tenant-a/doc-1","operation":"read"}]}`, "INVALID_TIME", "effectiveAt"},
		{"invalid time before extra field", `{"effectiveAt":"nope","queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read","extra":true}]}`, "INVALID_TIME", "effectiveAt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, errorObject := batchRawError(t, h, tc.raw)
			if status != http.StatusBadRequest || errorObject["type"] != tc.wantType || errorObject["field"] != tc.wantField {
				t.Fatalf("error = %d %v, want %s/%s", status, errorObject, tc.wantType, tc.wantField)
			}
		})
	}
}
