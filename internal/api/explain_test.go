package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func explain(h *apiHarness, body map[string]any) map[string]any {
	h.t.Helper()
	recorder := h.request(http.MethodPost, "/authorize/explain", body)
	h.mustStatus(recorder, http.StatusOK)
	return mustJSON(h.t, recorder)
}

// seedInherited adds viewer -> base inheritance with the permission carried by
// base and a tenant-a/* scope on base.
func seedInherited(h *apiHarness) {
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
}

func explainTriple(at string) map[string]any {
	body := map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"}
	if at != "" {
		body["effectiveAt"] = at
	}
	return body
}

func TestExplainInheritedRolePath(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedInherited(h)

	response := explain(h, explainTriple("2026-02-01T00:00:00Z"))
	if response["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("effectiveAt = %v", response["effectiveAt"])
	}
	decision := response["decision"].(map[string]any)
	if decision["granted"] != true || decision["matchedRole"] != "base" ||
		decision["matchedPermission"] != "doc-read" || decision["matchedScope"] != "tenant-a/*" {
		t.Fatalf("decision = %v", decision)
	}
	paths := response["paths"].([]any)
	if len(paths) != 1 {
		t.Fatalf("paths = %v", paths)
	}
	want := map[string]any{
		"source": "ROLE", "boundRole": "viewer", "role": "base",
		"permission": "doc-read", "scope": "tenant-a/*",
	}
	if !reflect.DeepEqual(paths[0], want) {
		t.Fatalf("path = %v, want %v", paths[0], want)
	}
}

func TestExplainDirectPathAndSortedMultiplePaths(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedInherited(h)
	// An exact-scope direct permission grant and a second bound role editor
	// with its own prefix scope both cover the queried resource.
	h.mustStatus(h.request(http.MethodPut, "/roles/editor", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/editor",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/editor/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "editor", "scope": "*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)

	response := explain(h, explainTriple("2026-02-01T00:00:00Z"))
	decision := response["decision"].(map[string]any)
	// The exact direct scope is the most specific path, so the reported
	// match keeps matchedRole null.
	if decision["granted"] != true || decision["matchedRole"] != nil ||
		decision["matchedPermission"] != "doc-read" || decision["matchedScope"] != "tenant-a/doc-1" {
		t.Fatalf("decision = %v", decision)
	}
	paths := response["paths"].([]any)
	// DIRECT_PERMISSION sorts before ROLE; role paths order by boundRole.
	wantOrder := []map[string]any{
		{"source": "DIRECT_PERMISSION", "boundRole": nil, "role": nil,
			"permission": "doc-read", "scope": "tenant-a/doc-1"},
		{"source": "ROLE", "boundRole": "editor", "role": "editor",
			"permission": "doc-read", "scope": "*"},
		{"source": "ROLE", "boundRole": "viewer", "role": "base",
			"permission": "doc-read", "scope": "tenant-a/*"},
	}
	if len(paths) != len(wantOrder) {
		t.Fatalf("paths = %v", paths)
	}
	for i, want := range wantOrder {
		if !reflect.DeepEqual(paths[i], want) {
			t.Fatalf("path[%d] = %v, want %v", i, paths[i], want)
		}
	}

	// The decision is byte-for-byte the same conclusion as POST /authorize.
	authorizeDecision := authorize(h, explainTriple("2026-02-01T00:00:00Z"))
	if !reflect.DeepEqual(authorizeDecision, decision) {
		t.Fatalf("decisions differ: %v vs %v", authorizeDecision, decision)
	}
}

func TestExplainDenialsCarryEmptyPaths(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	cases := []struct {
		setup  func()
		reason string
	}{
		{func() {}, "NO_ROLE_BINDING"},
		{func() {
			h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
				map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
		}, "NO_PERMISSION_BINDING"},
		{func() {
			h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
				map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
			h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
				map[string]any{"role": "viewer", "scope": "other/resource", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
		}, "OUT_OF_SCOPE"},
		{func() {
			h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
				map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2027-01-01T00:00:00Z"}), http.StatusOK)
		}, "NOT_EFFECTIVE"},
	}
	for _, tc := range cases {
		tc.setup()
		response := explain(h, explainTriple("2026-02-01T00:00:00Z"))
		decision := response["decision"].(map[string]any)
		if decision["granted"] != false || decision["reason"] != tc.reason {
			t.Fatalf("decision = %v, want reason %s", decision, tc.reason)
		}
		if paths := response["paths"].([]any); len(paths) != 0 {
			t.Fatalf("paths = %v, want empty", paths)
		}
	}
}

func TestExplainHalfOpenBoundary(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedInherited(h)
	// Close the scope interval at 2026-06-01.
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/scopes",
		map[string]any{"role": "base", "scope": "tenant-a/*", "effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)

	atStart := explain(h, explainTriple("2026-01-01T00:00:00Z"))
	if atStart["decision"].(map[string]any)["granted"] != true {
		t.Fatalf("start boundary = %v", atStart)
	}
	atEnd := explain(h, explainTriple("2026-06-01T00:00:00Z"))
	decision := atEnd["decision"].(map[string]any)
	if decision["granted"] != false || decision["reason"] != "NOT_EFFECTIVE" {
		t.Fatalf("end boundary = %v", decision)
	}
	if paths := atEnd["paths"].([]any); len(paths) != 0 {
		t.Fatalf("end paths = %v", paths)
	}
}

func TestExplainCanonicalTimeAndDefault(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedInherited(h)

	response := explain(h, explainTriple("2026-02-01T08:00:00+08:00"))
	if response["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("canonical effectiveAt = %v", response["effectiveAt"])
	}

	before := time.Now().UTC()
	response = explain(h, explainTriple(""))
	after := time.Now().UTC()
	parsed, err := time.Parse(time.RFC3339, response["effectiveAt"].(string))
	if err != nil {
		t.Fatalf("parse default effectiveAt: %v", err)
	}
	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Fatalf("default effectiveAt %v not near now (%v..%v)", parsed, before, after)
	}
	if len(response["paths"].([]any)) != 1 {
		t.Fatalf("default paths = %v", response["paths"])
	}
}

func TestExplainErrorContract(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)

	expect := func(rawBody string, wantType, wantField string, wantStatus int) {
		t.Helper()
		recorder := h.raw(http.MethodPost, "/authorize/explain", rawBody)
		h.mustStatus(recorder, wantStatus)
		errorObject := mustJSON(t, recorder)["error"].(map[string]any)
		gotField, _ := errorObject["field"].(string)
		if errorObject["type"] != wantType || gotField != wantField {
			t.Fatalf("error = %v, want %s/%s", errorObject, wantType, wantField)
		}
	}

	// Body must be a JSON object, not an array or scalar.
	expect(`["user-1"]`, "INVALID_REQUEST", "", http.StatusBadRequest)
	expect(`"user-1"`, "INVALID_REQUEST", "", http.StatusBadRequest)
	expect(``, "INVALID_REQUEST", "", http.StatusBadRequest)
	// Missing required fields and unknown fields.
	expect(`{"resource":"tenant-a/doc-1","operation":"read"}`, "INVALID_REQUEST", "subject", http.StatusBadRequest)
	expect(`{"subject":"user-1","operation":"read"}`, "INVALID_REQUEST", "resource", http.StatusBadRequest)
	expect(`{"subject":"user-1","resource":"tenant-a/doc-1"}`, "INVALID_REQUEST", "operation", http.StatusBadRequest)
	expect(`{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read","bogus":1}`,
		"INVALID_REQUEST", "", http.StatusBadRequest)
	// Identifier grammar.
	expect(`{"subject":"bad id","resource":"tenant-a/doc-1","operation":"read"}`,
		"INVALID_REQUEST", "subject", http.StatusBadRequest)
	expect(`{"subject":"user-1","resource":"tenant-a/doc-1","operation":"/read"}`,
		"INVALID_REQUEST", "operation", http.StatusBadRequest)

	// Registered triple but unknown members, first problem wins.
	expect(`{"subject":"ghost","resource":"tenant-a/doc-1","operation":"read"}`,
		"NOT_FOUND", "subject", http.StatusNotFound)
	expect(`{"subject":"user-1","resource":"ghost/x","operation":"read"}`,
		"NOT_FOUND", "resource", http.StatusNotFound)
	expect(`{"subject":"user-1","resource":"tenant-a/doc-1","operation":"delete"}`,
		"NOT_FOUND", "operation", http.StatusNotFound)

	// Invalid time is the single INVALID_TIME outcome and outranks the triple.
	expect(`{"subject":"ghost","resource":"tenant-a/doc-1","operation":"read","effectiveAt":"soon"}`,
		"INVALID_TIME", "effectiveAt", http.StatusBadRequest)
	expect(`{"subject":"bad id","resource":"x","operation":"y","effectiveAt":"2026-13-01T00:00:00Z"}`,
		"INVALID_TIME", "effectiveAt", http.StatusBadRequest)
}

func TestExplainIsReadOnly(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	seedInherited(h)
	target := "/history?subject=user-1&resource=" + enc("tenant-a/doc-1") + "&operation=read"
	before := history(h, target)["events"].([]any)
	explain(h, explainTriple("2026-02-01T00:00:00Z"))
	after := history(h, target)["events"].([]any)
	if len(before) != len(after) {
		t.Fatalf("history changed by explain: %d vs %d", len(before), len(after))
	}
}

func TestExplainRejectsNonObjectShape(t *testing.T) {
	h := newHarness(t)
	recorder := h.raw(http.MethodPost, "/authorize/explain", `{"subject":123,"resource":"tenant-a/doc-1","operation":"read"}`)
	h.mustStatus(recorder, http.StatusBadRequest)
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"].(map[string]any)["type"] != "INVALID_REQUEST" {
		t.Fatalf("error = %v", body)
	}
}
