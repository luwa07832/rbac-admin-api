package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func explain(h *apiHarness, body map[string]any) map[string]any {
	h.t.Helper()
	recorder := h.request(http.MethodPost, "/authorize/explain", body)
	h.mustStatus(recorder, http.StatusOK)
	return mustJSON(h.t, recorder)
}

func explainError(t *testing.T, h *apiHarness, body map[string]any, wantStatus int) map[string]any {
	t.Helper()
	recorder := h.request(http.MethodPost, "/authorize/explain", body)
	h.mustStatus(recorder, wantStatus)
	return mustJSON(t, recorder)["error"].(map[string]any)
}

func TestExplainListsAllCoveringPaths(t *testing.T) {
	h := newHarness(t)
	seedSubjectGraph(h)

	body := map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T00:00:00Z",
	}
	view := explain(h, body)
	if view["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("effectiveAt = %v", view["effectiveAt"])
	}
	if decision := view["decision"]; !reflect.DeepEqual(decision, authorize(h, body)) {
		t.Fatalf("decision = %v, authorize = %v", decision, authorize(h, body))
	}
	wantDecision := map[string]any{
		"granted": true, "matchedRole": nil,
		"matchedPermission": "doc-read", "matchedScope": "tenant-a/doc-1",
	}
	if !reflect.DeepEqual(view["decision"], wantDecision) {
		t.Fatalf("decision = %v", view["decision"])
	}
	wantPaths := []any{
		wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1"),
		wantPath("ROLE", "editor", "editor", "doc-read", "*"),
		wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*"),
	}
	if !reflect.DeepEqual(view["paths"], wantPaths) {
		raw, _ := json.Marshal(view["paths"])
		t.Fatalf("paths = %s", raw)
	}
}

func TestExplainRolePathCarriesBoundAndInheritedRole(t *testing.T) {
	h := newHarness(t)
	seedSubjectGraph(h)

	body := map[string]any{
		"subject": "user-2", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T00:00:00Z",
	}
	view := explain(h, body)
	wantDecision := map[string]any{
		"granted": true, "matchedRole": "base",
		"matchedPermission": "doc-read", "matchedScope": "tenant-a/*",
	}
	if !reflect.DeepEqual(view["decision"], wantDecision) {
		t.Fatalf("decision = %v", view["decision"])
	}
	wantPaths := []any{
		wantPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*"),
		wantPath("ROLE", "viewer", "base", "perm-b", "tenant-a/*"),
	}
	if !reflect.DeepEqual(view["paths"], wantPaths) {
		raw, _ := json.Marshal(view["paths"])
		t.Fatalf("paths = %s", raw)
	}
}

func TestExplainDenialReasonsReturnEmptyPaths(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	triple := map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T00:00:00Z",
	}
	assertDenied := func(wantReason string) {
		t.Helper()
		recorder := h.request(http.MethodPost, "/authorize/explain", triple)
		h.mustStatus(recorder, http.StatusOK)
		if !strings.Contains(recorder.Body.String(), `"paths":[]`) {
			t.Fatalf("paths must render as an empty array: %s", recorder.Body.String())
		}
		view := mustJSON(t, recorder)
		if !reflect.DeepEqual(view["paths"], []any{}) {
			t.Fatalf("paths = %v", view["paths"])
		}
		wantDecision := map[string]any{"granted": false, "reason": wantReason}
		if !reflect.DeepEqual(view["decision"], wantDecision) {
			t.Fatalf("decision = %v, want %v", view["decision"], wantDecision)
		}
		if decision := authorize(h, triple); !reflect.DeepEqual(view["decision"], decision) {
			t.Fatalf("decision = %v, authorize = %v", view["decision"], decision)
		}
	}

	assertDenied("NO_ROLE_BINDING")

	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	assertDenied("NO_PERMISSION_BINDING")

	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	assertDenied("OUT_OF_SCOPE")

	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-15T00:00:00Z"}), http.StatusOK)
	assertDenied("NOT_EFFECTIVE")
}

func TestExplainNormalizesEffectiveAt(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	grantAt(h, "/subjects/user-1/bindings/viewer", nil)
	grantAt(h, "/roles/viewer/permissions/doc-read", nil)
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "viewer", "scope": "tenant-a/*"})

	view := explain(h, map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T08:00:00+08:00",
	})
	if view["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("effectiveAt = %v", view["effectiveAt"])
	}
}

func TestExplainDefaultTimeIsCurrentAndReadOnly(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	// Grants active from 2020 are certainly active at the server's now.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)

	historyTarget := "/history?subject=user-1&resource=" + enc("tenant-a/doc-1") + "&operation=read"
	eventsBefore := history(h, historyTarget)["events"]
	before := time.Now().UTC()
	view := explain(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"})
	after := time.Now().UTC()

	effectiveAt, ok := view["effectiveAt"].(string)
	if !ok || effectiveAt == "" {
		t.Fatalf("effectiveAt = %v", view["effectiveAt"])
	}
	parsed, err := time.Parse(time.RFC3339, effectiveAt)
	if err != nil {
		t.Fatalf("effectiveAt %q does not parse: %v", effectiveAt, err)
	}
	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Fatalf("effectiveAt %v outside [%v, %v]", parsed, before, after)
	}
	if decision := view["decision"].(map[string]any); decision["granted"] != true {
		t.Fatalf("decision = %v", decision)
	}

	// The explanation is read-only: history is untouched and repeating the
	// call yields the same outcome.
	if eventsAfter := history(h, historyTarget)["events"]; !reflect.DeepEqual(eventsBefore, eventsAfter) {
		t.Fatalf("history changed: %v -> %v", eventsBefore, eventsAfter)
	}
	again := explain(h, map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"})
	if !reflect.DeepEqual(again["decision"], view["decision"]) || !reflect.DeepEqual(again["paths"], view["paths"]) {
		t.Fatalf("repeat explain differs: %v vs %v", again, view)
	}
}

func TestExplainErrorContract(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	// Body shape failures.
	recorder := h.raw(http.MethodPost, "/authorize/explain", `[1,2]`)
	h.mustStatus(recorder, http.StatusBadRequest)
	if errorObject := mustJSON(t, recorder)["error"].(map[string]any); errorObject["type"] != "INVALID_REQUEST" {
		t.Fatalf("non-object error = %v", errorObject)
	}
	recorder = h.raw(http.MethodPost, "/authorize/explain", `{"subject":"user-1","sneaky":1}`)
	h.mustStatus(recorder, http.StatusBadRequest)
	if errorObject := mustJSON(t, recorder)["error"].(map[string]any); errorObject["type"] != "INVALID_REQUEST" {
		t.Fatalf("unknown-field error = %v", errorObject)
	}

	// Missing or malformed identifiers report the first broken field.
	invalid := func(body map[string]any, wantField string) {
		t.Helper()
		errorObject := explainError(t, h, body, http.StatusBadRequest)
		if errorObject["type"] != "INVALID_REQUEST" || errorObject["field"] != wantField {
			t.Fatalf("error = %v, want INVALID_REQUEST field %s", errorObject, wantField)
		}
	}
	invalid(map[string]any{"resource": "tenant-a/doc-1", "operation": "read"}, "subject")
	invalid(map[string]any{"subject": "user-1", "operation": "read"}, "resource")
	invalid(map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1"}, "operation")
	invalid(map[string]any{"subject": "bad id", "resource": "tenant-a/doc-1", "operation": "read"}, "subject")
	invalid(map[string]any{"subject": "user-1", "resource": "bad//id", "operation": "read"}, "resource")
	invalid(map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "bad id"}, "operation")

	// Well-formed but unregistered identifiers report the first missing one.
	unknown := func(body map[string]any, wantField string) {
		t.Helper()
		errorObject := explainError(t, h, body, http.StatusNotFound)
		if errorObject["type"] != "NOT_FOUND" || errorObject["field"] != wantField {
			t.Fatalf("error = %v, want NOT_FOUND field %s", errorObject, wantField)
		}
	}
	unknown(map[string]any{"subject": "ghost", "resource": "tenant-a/doc-1", "operation": "read"}, "subject")
	unknown(map[string]any{"subject": "user-1", "resource": "ghost/x", "operation": "read"}, "resource")
	unknown(map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "delete"}, "operation")

	// A malformed effectiveAt is the only failure that outranks the triple.
	errorObject := explainError(t, h, map[string]any{
		"subject": "ghost", "resource": "ghost/x", "operation": "delete", "effectiveAt": "not-a-time",
	}, http.StatusBadRequest)
	if errorObject["type"] != "INVALID_TIME" || errorObject["field"] != "effectiveAt" {
		t.Fatalf("error = %v, want INVALID_TIME field effectiveAt", errorObject)
	}
	errorObject = explainError(t, h, map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-13-01T00:00:00Z",
	}, http.StatusBadRequest)
	if errorObject["type"] != "INVALID_TIME" || errorObject["field"] != "effectiveAt" {
		t.Fatalf("error = %v, want INVALID_TIME field effectiveAt", errorObject)
	}
}
