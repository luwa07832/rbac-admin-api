package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func batchExplainRaw(h *apiHarness, body string) map[string]any {
	h.t.Helper()
	recorder := h.raw(http.MethodPost, "/authorize/batch/explain", body)
	h.mustStatus(recorder, http.StatusOK)
	return mustJSON(h.t, recorder)
}

func batchExplain(h *apiHarness, body map[string]any) map[string]any {
	h.t.Helper()
	return batchExplainRaw(h, mustJSONBody(h.t, body))
}

func mustJSONBody(t *testing.T, body any) string {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

func explanationAt(t *testing.T, view map[string]any, index int) map[string]any {
	items, ok := view["explanations"].([]any)
	if !ok {
		t.Fatalf("missing explanations: %v", view)
	}
	return items[index].(map[string]any)
}

func TestAuthorizeBatchExplainSuccessAndDenial(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	view := batchExplain(h, map[string]any{
		"effectiveAt": "2026-02-01T00:00:00Z",
		"queries": []any{
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
			map[string]any{"subject": "user-2", "resource": "tenant-a/doc-1", "operation": "read"},
			map[string]any{"subject": "user-1", "resource": "tenant-b/doc-2", "operation": "read"},
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "audit"},
			map[string]any{"subject": "user-1", "resource": "tenant-b/doc-2", "operation": "write"},
		},
	})
	if view["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("effectiveAt = %v", view["effectiveAt"])
	}
	items := view["explanations"].([]any)
	if len(items) != 5 {
		t.Fatalf("explanations = %v", items)
	}

	granted := items[0].(map[string]any)
	if granted["subject"] != "user-1" || granted["resource"] != "tenant-a/doc-1" || granted["operation"] != "read" {
		t.Fatalf("echo = %v", granted)
	}
	wantDecision := map[string]any{
		"granted": true, "matchedRole": nil,
		"matchedPermission": "doc-read", "matchedScope": "tenant-a/doc-1",
	}
	if !reflect.DeepEqual(granted["decision"], wantDecision) {
		t.Fatalf("granted decision = %v", granted["decision"])
	}
	wantPaths := []any{
		wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1"),
	}
	if !reflect.DeepEqual(granted["paths"], wantPaths) {
		raw, _ := json.Marshal(granted["paths"])
		t.Fatalf("paths = %s", raw)
	}

	wantReasons := []string{"NO_ROLE_BINDING", "OUT_OF_SCOPE", "NO_PERMISSION_BINDING", "OUT_OF_SCOPE"}
	for index, reason := range wantReasons {
		item := items[index+1].(map[string]any)
		decision := item["decision"].(map[string]any)
		if decision["granted"] != false || decision["reason"] != reason || len(decision) != 2 {
			t.Fatalf("[%d] decision = %v, want reason %s", index+1, decision, reason)
		}
		if !reflect.DeepEqual(item["paths"], []any{}) {
			t.Fatalf("[%d] denied paths = %v, want []", index+1, item["paths"])
		}
	}
}

func TestAuthorizeBatchExplainListsAllPathsWithStableOrder(t *testing.T) {
	h := newHarness(t)
	seedSubjectGraph(h)

	view := batchExplain(h, map[string]any{
		"effectiveAt": "2026-02-01T00:00:00Z",
		"queries": []any{
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
			map[string]any{"subject": "user-2", "resource": "tenant-a/doc-1", "operation": "read"},
		},
	})
	first := explanationAt(t, view, 0)
	wantFirst := []any{
		wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1"),
		wantPath("ROLE", "editor", "editor", "doc-read", "*"),
		wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*"),
	}
	if !reflect.DeepEqual(first["paths"], wantFirst) {
		raw, _ := json.Marshal(first["paths"])
		t.Fatalf("user-1 paths = %s", raw)
	}
	singleFirst := explain(h, map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T00:00:00Z",
	})
	if !reflect.DeepEqual(first["decision"], singleFirst["decision"]) {
		t.Fatalf("decision = %v, single = %v", first["decision"], singleFirst["decision"])
	}

	second := explanationAt(t, view, 1)
	wantSecond := []any{
		wantPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*"),
		wantPath("ROLE", "viewer", "base", "perm-b", "tenant-a/*"),
	}
	if !reflect.DeepEqual(second["paths"], wantSecond) {
		raw, _ := json.Marshal(second["paths"])
		t.Fatalf("user-2 paths = %s", raw)
	}
}

func TestAuthorizeBatchExplainMatchesSingleAndKeepsOrder(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	triples := []struct{ subject, resource, operation string }{
		{"user-1", "tenant-b/doc-2", "read"},
		{"user-2", "tenant-a/doc-1", "read"},
		{"user-1", "tenant-a/doc-1", "read"},
		{"user-1", "tenant-a/doc-1", "read"},
	}
	queries := make([]any, len(triples))
	for index, query := range triples {
		queries[index] = map[string]any{
			"subject": query.subject, "resource": query.resource, "operation": query.operation,
		}
	}
	view := batchExplain(h, map[string]any{"effectiveAt": "2026-02-01T00:00:00Z", "queries": queries})
	items := view["explanations"].([]any)
	if len(items) != len(triples) {
		t.Fatalf("explanations = %v", items)
	}
	for index, query := range triples {
		single := explain(h, map[string]any{
			"subject": query.subject, "resource": query.resource, "operation": query.operation,
			"effectiveAt": "2026-02-01T00:00:00Z",
		})
		got := items[index].(map[string]any)
		if got["subject"] != query.subject || got["resource"] != query.resource || got["operation"] != query.operation {
			t.Fatalf("[%d] echo = %v", index, got)
		}
		if !reflect.DeepEqual(got["decision"], single["decision"]) {
			t.Fatalf("[%d] decision %v != single %v", index, got["decision"], single["decision"])
		}
		if !reflect.DeepEqual(got["paths"], single["paths"]) {
			t.Fatalf("[%d] paths %v != single %v", index, got["paths"], single["paths"])
		}
	}
	// Duplicate triples are not merged and stay in input order.
	dup := items[2].(map[string]any)
	other := items[3].(map[string]any)
	if !reflect.DeepEqual(dup, other) {
		t.Fatalf("duplicate explanations diverged: %v vs %v", dup, other)
	}
}

func TestAuthorizeBatchExplainNotEffectiveEmptyPaths(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	view := batchExplain(h, map[string]any{
		"effectiveAt": "2025-12-01T00:00:00Z",
		"queries": []any{
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
		},
	})
	item := explanationAt(t, view, 0)
	wantDecision := map[string]any{"granted": false, "reason": "NOT_EFFECTIVE"}
	if !reflect.DeepEqual(item["decision"], wantDecision) {
		t.Fatalf("decision = %v", item["decision"])
	}
	if !reflect.DeepEqual(item["paths"], []any{}) {
		t.Fatalf("paths = %v", item["paths"])
	}
}

func TestAuthorizeBatchExplainDeduplicatesOverlappingVersions(t *testing.T) {
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

	view := batchExplain(h, map[string]any{
		"effectiveAt": "2026-04-01T00:00:00Z",
		"queries": []any{
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
		},
	})
	for index := 0; index < 2; index++ {
		item := explanationAt(t, view, index)
		wantPaths := []any{wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*")}
		if !reflect.DeepEqual(item["paths"], wantPaths) {
			t.Fatalf("[%d] paths = %v", index, item["paths"])
		}
	}
}

func TestAuthorizeBatchExplainNormalizesAndDefaultsTimeAndIsReadOnly(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)

	view := batchExplain(h, map[string]any{
		"effectiveAt": "2026-02-01T08:00:00+08:00",
		"queries": []any{
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
		},
	})
	if view["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("effectiveAt = %v", view["effectiveAt"])
	}

	historyTarget := "/history?subject=user-1&resource=" + enc("tenant-a/doc-1") + "&operation=read"
	eventsBefore := history(h, historyTarget)["events"]
	before := time.Now().UTC()
	view = batchExplain(h, map[string]any{
		"queries": []any{
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
		},
	})
	after := time.Now().UTC()
	effectiveAt, _ := view["effectiveAt"].(string)
	parsed, err := time.Parse(time.RFC3339, effectiveAt)
	if err != nil {
		t.Fatalf("effectiveAt %q: %v", effectiveAt, err)
	}
	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Fatalf("default effectiveAt %v outside [%v, %v]", parsed, before, after)
	}
	if item := explanationAt(t, view, 0); item["decision"].(map[string]any)["granted"] != true {
		t.Fatalf("default-time decision = %v", item["decision"])
	}

	// Read-only: history is untouched and the query can repeat.
	if eventsAfter := history(h, historyTarget)["events"]; !reflect.DeepEqual(eventsBefore, eventsAfter) {
		t.Fatalf("history changed: %v -> %v", eventsBefore, eventsAfter)
	}
	again := batchExplain(h, map[string]any{
		"queries": []any{
			map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"},
		},
	})
	if !reflect.DeepEqual(explanationAt(t, again, 0), explanationAt(t, view, 0)) {
		t.Fatalf("repeat batch explain differs: %v vs %v", again, view)
	}

	// An explicit null effectiveAt is treated as omitted.
	view = batchExplain(h, map[string]any{
		"effectiveAt": nil,
		"queries":     []any{map[string]any{"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read"}},
	})
	if item := explanationAt(t, view, 0); item["decision"].(map[string]any)["granted"] != true {
		t.Fatalf("null effectiveAt decision = %v", item["decision"])
	}
}

func batchExplainExpectError(t *testing.T, h *apiHarness, body string, wantStatus int, wantType, wantField string) {
	t.Helper()
	recorder := h.raw(http.MethodPost, "/authorize/batch/explain", body)
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), wantStatus)
	}
	response := mustJSON(t, recorder)
	errorObject := response["error"].(map[string]any)
	field, _ := errorObject["field"].(string)
	if errorObject["type"] != wantType || field != wantField {
		t.Fatalf("error = %v, want type %s field %s", errorObject, wantType, wantField)
	}
	if _, ok := response["explanations"]; ok {
		t.Fatalf("error response leaked explanations: %s", recorder.Body.String())
	}
}

func TestAuthorizeBatchExplainStructureErrors(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)
	valid := `{"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`

	batchExplainExpectError(t, h, ``, http.StatusBadRequest, "INVALID_REQUEST", "")
	batchExplainExpectError(t, h, `[]`, http.StatusBadRequest, "INVALID_REQUEST", "")
	batchExplainExpectError(t, h, `null`, http.StatusBadRequest, "INVALID_REQUEST", "")
	batchExplainExpectError(t, h, `{"effectiveAt":"2026-02-01T00:00:00Z"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"queries":null}`, http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"queries":{}}`, http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"queries":"read"}`, http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"queries":[]}`, http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"queries":[], "effectiveAt":"2026-02-01T00:00:00Z"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"queries":[], "effectiveAt":"not-a-time"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"queries":[{"subject":"user-1"}],"extra":true}`,
		http.StatusBadRequest, "INVALID_REQUEST", "extra")
	batchExplainExpectError(t, h, strings.Replace(valid, `"queries"`, `"q"`, 1),
		http.StatusBadRequest, "INVALID_REQUEST", "q")

	queries := make([]string, 101)
	for index := range queries {
		queries[index] = `{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}`
	}
	batchExplainExpectError(t, h, `{"queries":[`+strings.Join(queries, ",")+`]}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
}

func TestAuthorizeBatchExplainItemErrorsAtomic(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	cases := []struct {
		name string
		body string
		typ  string
		fld  string
	}{
		{"missing subject", `{"queries":[{"resource":"tenant-a/doc-1","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[0].subject"},
		{"missing operation second index", `{"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1"}]}`,
			"INVALID_REQUEST", "queries[1].operation"},
		{"extra effectiveAt field", `{"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read","effectiveAt":"2026-02-01T00:00:00Z"}]}`,
			"INVALID_REQUEST", "queries[0].effectiveAt"},
		{"null item", `{"queries":[null]}`, "INVALID_REQUEST", "queries[0]"},
		{"array item", `{"queries":[["user-1"]]}`, "INVALID_REQUEST", "queries[0]"},
		{"number field", `{"queries":[{"subject":7,"resource":"r","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[0].subject"},
		{"bad grammar subject", `{"queries":[{"subject":"bad id","resource":"r","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[0].subject"},
		{"bad grammar resource", `{"queries":[{"subject":"user-1","resource":"bad/x/","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[0].resource"},
		{"bad grammar operation", `{"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"bad op"}]}`,
			"INVALID_REQUEST", "queries[0].operation"},
		{"unknown subject", `{"queries":[{"subject":"ghost","resource":"tenant-a/doc-1","operation":"read"}]}`,
			"NOT_FOUND", "queries[0].subject"},
		{"unknown resource", `{"queries":[{"subject":"user-1","resource":"ghost/x","operation":"read"}]}`,
			"NOT_FOUND", "queries[0].resource"},
		{"unknown operation", `{"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"delete"}]}`,
			"NOT_FOUND", "queries[0].operation"},
		{"first index not found wins", `{"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"ghost","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"delete"}]}`,
			"NOT_FOUND", "queries[1].subject"},
		// Even when the first query would grant, a later failure aborts the
		// whole batch: no explanations are returned.
		{"later grammar failure is atomic", `{"effectiveAt":"2026-02-01T00:00:00Z","queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"bad id","resource":"r","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[1].subject"},
		{"later not found is atomic", `{"effectiveAt":"2026-02-01T00:00:00Z","queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"ghost","resource":"tenant-a/doc-1","operation":"read"}]}`,
			"NOT_FOUND", "queries[1].subject"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus := http.StatusBadRequest
			if tc.typ == "NOT_FOUND" {
				wantStatus = http.StatusNotFound
			}
			batchExplainExpectError(t, h, tc.body, wantStatus, tc.typ, tc.fld)
		})
	}
}

func TestAuthorizeBatchExplainTimePriority(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	batchExplainExpectError(t, h, `{"effectiveAt":"not-a-time","queries":[
		{"subject":"ghost","resource":"bad r","operation":"read"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	batchExplainExpectError(t, h, `{"effectiveAt":"2026-13-01T00:00:00Z","queries":[
		{"resource":"r"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	batchExplainExpectError(t, h, `{"effectiveAt":7,"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	// Batch structure still outranks the time check.
	batchExplainExpectError(t, h, `{"effectiveAt":"not-a-time","queries":[]}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"effectiveAt":"not-a-time"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
}

func TestAuthorizeBatchExplainAcceptsExactlyOneHundred(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	queries := make([]any, 100)
	for index := range queries {
		queries[index] = map[string]any{"subject": "user-2", "resource": "tenant-a/doc-1", "operation": "read"}
	}
	view := batchExplain(h, map[string]any{
		"effectiveAt": "2026-02-01T00:00:00Z",
		"queries":     queries,
	})
	items := view["explanations"].([]any)
	if len(items) != 100 {
		t.Fatalf("explanations len = %d", len(items))
	}
	for index, raw := range items {
		item := raw.(map[string]any)
		if item["subject"] != "user-2" || item["decision"].(map[string]any)["reason"] != "NO_ROLE_BINDING" {
			t.Fatalf("[%d] item = %v", index, item)
		}
		if !reflect.DeepEqual(item["paths"], []any{}) {
			t.Fatalf("[%d] paths = %v", index, item["paths"])
		}
	}
}

func TestAuthorizeBatchExplainExistingEntriesUnchanged(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	body := fmt.Sprintf(`{"effectiveAt":"2026-02-01T00:00:00Z","queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	recorder := h.raw(http.MethodPost, "/authorize/batch/explain", body)
	h.mustStatus(recorder, http.StatusOK)
	batchItem := mustJSON(t, recorder)["explanations"].([]any)[0].(map[string]any)

	recorder = h.raw(http.MethodPost, "/authorize/explain", `{
		"subject":"user-1","resource":"tenant-a/doc-1","operation":"read",
		"effectiveAt":"2026-02-01T00:00:00Z"}`)
	h.mustStatus(recorder, http.StatusOK)
	single := mustJSON(t, recorder)
	if !reflect.DeepEqual(batchItem["decision"], single["decision"]) ||
		!reflect.DeepEqual(batchItem["paths"], single["paths"]) {
		t.Fatalf("batch item %v != single %v", batchItem, single)
	}

	// The plain batch authorize entry keeps its decisions-only shape.
	recorder = h.raw(http.MethodPost, "/authorize/batch", body)
	h.mustStatus(recorder, http.StatusOK)
	batchEnvelope := mustJSON(t, recorder)
	if _, ok := batchEnvelope["explanations"]; ok {
		t.Fatalf("batch authorize leaked explanations: %s", recorder.Body.String())
	}
	if _, ok := batchEnvelope["decisions"]; !ok {
		t.Fatalf("batch authorize lost decisions: %s", recorder.Body.String())
	}
}
