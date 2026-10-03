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

func explanationsOf(t *testing.T, envelope map[string]any) []any {
	t.Helper()
	items, ok := envelope["explanations"].([]any)
	if !ok {
		t.Fatalf("missing explanations: %v", envelope)
	}
	return items
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

func TestAuthorizeBatchExplainListsAllPaths(t *testing.T) {
	h := newHarness(t)
	seedSubjectGraph(h)

	envelope := batchExplainRaw(h, `{
		"effectiveAt":"2026-02-01T00:00:00Z",
		"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-2","resource":"tenant-a/doc-1","operation":"read"}
		]}`)
	if envelope["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("effectiveAt = %v", envelope["effectiveAt"])
	}
	items := explanationsOf(t, envelope)
	if len(items) != 2 {
		t.Fatalf("explanations = %v", items)
	}

	first := items[0].(map[string]any)
	if first["subject"] != "user-1" || first["resource"] != "tenant-a/doc-1" || first["operation"] != "read" {
		t.Fatalf("first echo = %v", first)
	}
	wantDecision := map[string]any{
		"granted": true, "matchedRole": nil,
		"matchedPermission": "doc-read", "matchedScope": "tenant-a/doc-1",
	}
	if !reflect.DeepEqual(first["decision"], wantDecision) {
		t.Fatalf("first decision = %v", first["decision"])
	}
	wantPaths := []any{
		wantPath("DIRECT_PERMISSION", nil, nil, "doc-read", "tenant-a/doc-1"),
		wantPath("ROLE", "editor", "editor", "doc-read", "*"),
		wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*"),
	}
	if !reflect.DeepEqual(first["paths"], wantPaths) {
		raw, _ := json.Marshal(first["paths"])
		t.Fatalf("first paths = %s", raw)
	}

	second := items[1].(map[string]any)
	wantSecondDecision := map[string]any{
		"granted": true, "matchedRole": "base",
		"matchedPermission": "doc-read", "matchedScope": "tenant-a/*",
	}
	if !reflect.DeepEqual(second["decision"], wantSecondDecision) {
		t.Fatalf("second decision = %v", second["decision"])
	}
	wantSecondPaths := []any{
		wantPath("ROLE", "viewer", "base", "doc-read", "tenant-a/*"),
		wantPath("ROLE", "viewer", "base", "perm-b", "tenant-a/*"),
	}
	if !reflect.DeepEqual(second["paths"], wantSecondPaths) {
		raw, _ := json.Marshal(second["paths"])
		t.Fatalf("second paths = %s", raw)
	}
}

func TestAuthorizeBatchExplainDenialsReturnEmptyPaths(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	envelope := batchExplainRaw(h, `{
		"effectiveAt":"2026-02-01T00:00:00Z",
		"queries":[
			{"subject":"user-2","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"audit"},
			{"subject":"user-1","resource":"tenant-b/doc-2","operation":"write"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}
		]}`)
	items := explanationsOf(t, envelope)
	want := []string{"NO_ROLE_BINDING", "NO_PERMISSION_BINDING", "OUT_OF_SCOPE", ""}
	for index, reason := range want {
		item := items[index].(map[string]any)
		decision := item["decision"].(map[string]any)
		if reason == "" {
			if decision["granted"] != true {
				t.Fatalf("[%d] decision = %v, want granted", index, decision)
			}
			if paths := item["paths"].([]any); len(paths) == 0 {
				t.Fatalf("[%d] granted explanation has no paths", index)
			}
			continue
		}
		if decision["granted"] != false || decision["reason"] != reason || len(decision) != 2 {
			t.Fatalf("[%d] decision = %v, want denial %s", index, decision, reason)
		}
		if paths := item["paths"].([]any); len(paths) != 0 {
			t.Fatalf("[%d] denial paths = %v, want empty", index, paths)
		}
	}
}

func TestAuthorizeBatchExplainNotEffective(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	envelope := batchExplainRaw(h, `{
		"effectiveAt":"2025-12-01T00:00:00Z",
		"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}
		]}`)
	item := explanationsOf(t, envelope)[0].(map[string]any)
	decision := item["decision"].(map[string]any)
	if decision["granted"] != false || decision["reason"] != "NOT_EFFECTIVE" || len(decision) != 2 {
		t.Fatalf("decision = %v", decision)
	}
	if paths := item["paths"].([]any); len(paths) != 0 {
		t.Fatalf("paths = %v, want empty", paths)
	}
}

func TestAuthorizeBatchExplainMatchesSingleInOrder(t *testing.T) {
	h := newHarness(t)
	seedSubjectGraph(h)

	triples := []struct{ subject, resource, operation string }{
		{"user-2", "tenant-a/doc-1", "read"},
		{"user-1", "tenant-a/doc-1", "read"},
		{"user-3", "tenant-a/doc-1", "read"},
		{"user-1", "tenant-b/doc-2", "read"},
	}
	rawQueries := ""
	for index, query := range triples {
		if index > 0 {
			rawQueries += ","
		}
		rawQueries += fmt.Sprintf(`{"subject":%q,"resource":%q,"operation":%q}`,
			query.subject, query.resource, query.operation)
	}
	envelope := batchExplainRaw(h, `{"effectiveAt":"2026-02-01T00:00:00Z","queries":[`+rawQueries+`]}`)
	if envelope["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("effectiveAt = %v", envelope["effectiveAt"])
	}
	items := explanationsOf(t, envelope)
	if len(items) != len(triples) {
		t.Fatalf("explanations = %v", items)
	}
	for index, query := range triples {
		item := items[index].(map[string]any)
		if item["subject"] != query.subject || item["resource"] != query.resource || item["operation"] != query.operation {
			t.Fatalf("[%d] echo = %v", index, item)
		}
		recorder := h.request(http.MethodPost, "/authorize/explain", map[string]any{
			"subject": query.subject, "resource": query.resource, "operation": query.operation,
			"effectiveAt": "2026-02-01T00:00:00Z",
		})
		h.mustStatus(recorder, http.StatusOK)
		single := mustJSON(t, recorder)
		if fmt.Sprint(item["decision"]) != fmt.Sprint(single["decision"]) {
			t.Fatalf("[%d] decision %v != single %v", index, item["decision"], single["decision"])
		}
		if fmt.Sprint(item["paths"]) != fmt.Sprint(single["paths"]) {
			t.Fatalf("[%d] paths %v != single %v", index, item["paths"], single["paths"])
		}
	}
}

func TestAuthorizeBatchExplainKeepsDuplicateQueries(t *testing.T) {
	h := newHarness(t)
	seedSubjectGraph(h)

	envelope := batchExplainRaw(h, `{
		"effectiveAt":"2026-02-01T00:00:00Z",
		"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}
		]}`)
	items := explanationsOf(t, envelope)
	if len(items) != 3 {
		t.Fatalf("explanations = %v", items)
	}
	first := items[0].(map[string]any)
	for index := 1; index < 3; index++ {
		other := items[index].(map[string]any)
		if fmt.Sprint(other["decision"]) != fmt.Sprint(first["decision"]) ||
			fmt.Sprint(other["paths"]) != fmt.Sprint(first["paths"]) {
			t.Fatalf("duplicate [%d] diverged: %v vs %v", index, other, first)
		}
	}
	if paths := first["paths"].([]any); len(paths) != 3 {
		t.Fatalf("paths = %v, want all three covering paths", paths)
	}
}

func TestAuthorizeBatchExplainDeduplicatesOverlappingVersions(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	grantAt(h, "/subjects/user-1/bindings/viewer", nil)
	grantAt(h, "/roles/viewer/permissions/doc-read", nil)
	grantAt(h, "/subjects/user-1/scopes", map[string]any{"role": "viewer", "scope": "tenant-a/*"})

	// Two overlapping binding intervals are active at the same moment; the
	// role path must collapse into a single explanation entry.
	h.mustStatus(h.request(http.MethodDelete, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-06-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-03-01T00:00:00Z"}), http.StatusOK)

	envelope := batchExplainRaw(h, `{
		"effectiveAt":"2026-04-01T00:00:00Z",
		"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}
		]}`)
	item := explanationsOf(t, envelope)[0].(map[string]any)
	wantPaths := []any{wantPath("ROLE", "viewer", "viewer", "doc-read", "tenant-a/*")}
	if !reflect.DeepEqual(item["paths"], wantPaths) {
		raw, _ := json.Marshal(item["paths"])
		t.Fatalf("paths = %s", raw)
	}
}

func TestAuthorizeBatchExplainNormalizesSharedTime(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	envelope := batchExplainRaw(h, `{
		"effectiveAt":"2026-02-01T08:00:00+08:00",
		"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-2","resource":"tenant-a/doc-1","operation":"read"}
		]}`)
	if envelope["effectiveAt"] != "2026-02-01T00:00:00Z" {
		t.Fatalf("effectiveAt = %v", envelope["effectiveAt"])
	}
	items := explanationsOf(t, envelope)
	if items[0].(map[string]any)["decision"].(map[string]any)["granted"] != true {
		t.Fatalf("first decision = %v", items[0])
	}
}

func TestAuthorizeBatchExplainDefaultsToCurrentAndReadOnly(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/permissions/doc-read",
		map[string]any{"effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2020-01-01T00:00:00Z"}), http.StatusOK)

	historyTarget := "/history?subject=user-1&resource=" + enc("tenant-a/doc-1") + "&operation=read"
	eventsBefore := history(h, historyTarget)["events"]
	before := time.Now().UTC()
	envelope := batchExplainRaw(h, `{"queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	after := time.Now().UTC()

	effectiveAt, ok := envelope["effectiveAt"].(string)
	if !ok || effectiveAt == "" {
		t.Fatalf("effectiveAt = %v", envelope["effectiveAt"])
	}
	parsed, err := time.Parse(time.RFC3339, effectiveAt)
	if err != nil {
		t.Fatalf("effectiveAt %q does not parse: %v", effectiveAt, err)
	}
	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Fatalf("effectiveAt %v outside [%v, %v]", parsed, before, after)
	}
	item := explanationsOf(t, envelope)[0].(map[string]any)
	if item["decision"].(map[string]any)["granted"] != true {
		t.Fatalf("decision = %v", item["decision"])
	}

	// The batch explanation is read-only: history is untouched and a second
	// call yields the same paths and decision.
	if eventsAfter := history(h, historyTarget)["events"]; !reflect.DeepEqual(eventsBefore, eventsAfter) {
		t.Fatalf("history changed: %v -> %v", eventsBefore, eventsAfter)
	}
	again := batchExplainRaw(h, `{"queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	againItem := explanationsOf(t, again)[0].(map[string]any)
	if fmt.Sprint(againItem["decision"]) != fmt.Sprint(item["decision"]) ||
		fmt.Sprint(againItem["paths"]) != fmt.Sprint(item["paths"]) {
		t.Fatalf("repeat call differs: %v vs %v", againItem, item)
	}

	// An explicit null effectiveAt behaves like an omitted one.
	nullEnvelope := batchExplainRaw(h, `{"effectiveAt":null,"queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	nullItem := explanationsOf(t, nullEnvelope)[0].(map[string]any)
	if nullItem["decision"].(map[string]any)["granted"] != true {
		t.Fatalf("null effectiveAt decision = %v", nullItem["decision"])
	}
}

func TestAuthorizeBatchExplainAtomicFailures(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	structureCases := []struct {
		name      string
		body      string
		wantType  string
		wantField string
	}{
		{"empty body", ``, "INVALID_REQUEST", ""},
		{"array body", `[]`, "INVALID_REQUEST", ""},
		{"null body", `null`, "INVALID_REQUEST", ""},
		{"missing queries", `{"effectiveAt":"2026-02-01T00:00:00Z"}`, "INVALID_REQUEST", "queries"},
		{"null queries", `{"queries":null}`, "INVALID_REQUEST", "queries"},
		{"empty queries", `{"queries":[]}`, "INVALID_REQUEST", "queries"},
		{"unknown top field", `{"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}],"who":1}`,
			"INVALID_REQUEST", "who"},
		{"extra field first", `{"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read","effectiveAt":"2026-02-01T00:00:00Z"}]}`,
			"INVALID_REQUEST", "queries[0].effectiveAt"},
		{"unknown extra first", `{"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read","who":1}]}`,
			"INVALID_REQUEST", "queries[0].who"},
		{"null item", `{"queries":[null]}`, "INVALID_REQUEST", "queries[0]"},
		{"array item", `{"queries":[["user-1"]]}`, "INVALID_REQUEST", "queries[0]"},
		{"number field", `{"queries":[{"subject":7,"resource":"r","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[0].subject"},
		{"null field", `{"queries":[{"subject":null,"resource":"r","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[0].subject"},
		{"bad grammar subject", `{"queries":[{"subject":"bad id","resource":"r","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[0].subject"},
		{"bad grammar resource", `{"queries":[{"subject":"user-1","resource":"bad/x/","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[0].resource"},
		{"bad grammar operation", `{"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"bad op"}]}`,
			"INVALID_REQUEST", "queries[0].operation"},
		{"grammar beats later index", `{"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"bad id","resource":"r","operation":"read"}]}`,
			"INVALID_REQUEST", "queries[2].subject"},
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
		{"shape before grammar same index", `{"queries":[
			{"resource":"bad r","operation":"read"},
			{"subject":"ghost"}]}`,
			"INVALID_REQUEST", "queries[0].subject"},
	}
	for _, tc := range structureCases {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus := http.StatusBadRequest
			if tc.wantType == "NOT_FOUND" {
				wantStatus = http.StatusNotFound
			}
			batchExplainExpectError(t, h, tc.body, wantStatus, tc.wantType, tc.wantField)
		})
	}
}

func TestAuthorizeBatchExplainTimePriority(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	// Invalid time beats every per-query failure, including grammar and missing members.
	batchExplainExpectError(t, h, `{"effectiveAt":"not-a-time","queries":[
		{"subject":"ghost","resource":"bad r","operation":"read"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	batchExplainExpectError(t, h, `{"effectiveAt":"2026-13-01T00:00:00Z","queries":[
		{"resource":"r"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	batchExplainExpectError(t, h, `{"effectiveAt":7,"queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	batchExplainExpectError(t, h, `{"effectiveAt":false,"queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	// Batch structure still outranks the time check.
	batchExplainExpectError(t, h, `{"effectiveAt":"not-a-time","queries":[]}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExplainExpectError(t, h, `{"effectiveAt":"not-a-time"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
}

func TestAuthorizeBatchExplainSizeBound(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	build := func(count int) string {
		var builder strings.Builder
		builder.WriteString(`{"effectiveAt":"2026-02-01T00:00:00Z","queries":[`)
		for index := 0; index < count; index++ {
			if index > 0 {
				builder.WriteString(",")
			}
			fmt.Fprintf(&builder, `{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}`)
		}
		builder.WriteString(`]}`)
		return builder.String()
	}

	envelope := batchExplainRaw(h, build(100))
	if items := explanationsOf(t, envelope); len(items) != 100 {
		t.Fatalf("len(explanations) = %d, want 100", len(items))
	}
	batchExplainExpectError(t, h, build(101), http.StatusBadRequest, "INVALID_REQUEST", "queries")
}

func TestAuthorizeBatchExplainKeepsExistingEntries(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	triple := map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T00:00:00Z",
	}
	singleBefore := authorize(h, triple)
	batchBefore := batchRaw(h, `{"effectiveAt":"2026-02-01T00:00:00Z","queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	historyTarget := "/history?subject=user-1&resource=" + enc("tenant-a/doc-1") + "&operation=read"
	historyBefore := history(h, historyTarget)["events"]

	batchExplainRaw(h, `{
		"effectiveAt":"2026-02-01T00:00:00Z",
		"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-2","resource":"tenant-a/doc-1","operation":"read"}]}`)

	singleAfter := authorize(h, triple)
	if !reflect.DeepEqual(singleBefore, singleAfter) {
		t.Fatalf("single authorize changed: %v -> %v", singleBefore, singleAfter)
	}
	batchAfter := batchRaw(h, `{"effectiveAt":"2026-02-01T00:00:00Z","queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	if fmt.Sprint(batchAfter.Decisions[0].Decision) != fmt.Sprint(batchBefore.Decisions[0].Decision) {
		t.Fatalf("batch decisions changed: %v -> %v", batchBefore, batchAfter)
	}
	if historyAfter := history(h, historyTarget)["events"]; !reflect.DeepEqual(historyBefore, historyAfter) {
		t.Fatalf("history changed: %v -> %v", historyBefore, historyAfter)
	}

	recorder := h.request(http.MethodPost, "/authorize/explain", triple)
	h.mustStatus(recorder, http.StatusOK)
	singleExplain := mustJSON(t, recorder)
	if fmt.Sprint(singleExplain["decision"]) != fmt.Sprint(singleAfter) {
		t.Fatalf("single explain decision %v != authorize %v", singleExplain["decision"], singleAfter)
	}
}
