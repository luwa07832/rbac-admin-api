package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func batchRaw(h *apiHarness, body string) *batchEnvelope {
	h.t.Helper()
	recorder := h.raw(http.MethodPost, "/authorize/batch", body)
	if recorder.Code != http.StatusOK {
		h.t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), http.StatusOK)
	}
	var envelope batchEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		h.t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	return &envelope
}

type batchEnvelope struct {
	Decisions []batchDecisionItem `json:"decisions"`
}

func seedBatchBaseline(h *apiHarness) {
	seedBaseline(h)
	h.mustStatus(h.request(http.MethodPut, "/roles/base", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/viewer/parents",
		map[string]any{"parents": []string{"base"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/viewer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/base/permissions/doc-read",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"role": "viewer", "scope": "tenant-a/*", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-read", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-2", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-write", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/permissions/doc-write/operations",
		map[string]any{"operations": []string{"write"}}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/operations/audit", nil), http.StatusOK)
	// writer carries doc-write (covering write) without any scope row, so a
	// write on an uncovered resource ends at OUT_OF_SCOPE.
	h.mustStatus(h.request(http.MethodPut, "/roles/writer", nil), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/bindings/writer",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	h.mustStatus(h.request(http.MethodPut, "/roles/writer/permissions/doc-write",
		map[string]any{"effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
	// doc-write covers the write operation but is scoped to tenant-a/doc-1
	// only, so writing tenant-b/doc-2 ends at the OUT_OF_SCOPE layer.
	h.mustStatus(h.request(http.MethodPut, "/subjects/user-1/scopes",
		map[string]any{"permission": "doc-write", "scope": "tenant-a/doc-1", "effectiveFrom": "2026-01-01T00:00:00Z"}), http.StatusOK)
}

func TestAuthorizeBatchGrantedDirectAndRole(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	envelope := batchRaw(h, `{
		"effectiveAt":"2026-02-01T00:00:00Z",
		"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-b/doc-2","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}
		]}`)
	if len(envelope.Decisions) != 3 {
		t.Fatalf("decisions = %s", envelope)
	}
	first := envelope.Decisions[0]
	if first.Subject != "user-1" || first.Resource != "tenant-a/doc-1" || first.Operation != "read" {
		t.Fatalf("first echo = %v", first)
	}
	if decision := first.Decision; decision["granted"] != true ||
		decision["matchedRole"] != nil || decision["matchedPermission"] != "doc-read" ||
		decision["matchedScope"] != "tenant-a/doc-1" {
		t.Fatalf("first decision = %v", first.Decision)
	}
	if count := len(first.Decision); count != 4 {
		t.Fatalf("granted decision has %d fields: %v", count, first.Decision)
	}
	denied := envelope.Decisions[1].Decision
	if denied["granted"] != false || denied["reason"] != "OUT_OF_SCOPE" || len(denied) != 2 {
		t.Fatalf("denied decision = %v", denied)
	}
	third := envelope.Decisions[2].Decision
	if third["granted"] != true || third["matchedRole"] != nil ||
		third["matchedPermission"] != "doc-read" || third["matchedScope"] != "tenant-a/doc-1" {
		t.Fatalf("third decision = %v", third)
	}
}

func TestAuthorizeBatchDenialReasons(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	envelope := batchRaw(h, `{
		"effectiveAt":"2026-02-01T00:00:00Z",
		"queries":[
			{"subject":"user-2","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"audit"},
			{"subject":"user-1","resource":"tenant-b/doc-2","operation":"write"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"write"}
		]}`)
	want := []struct {
		reason  string
		granted bool
	}{
		{"NO_ROLE_BINDING", false},
		{"NO_PERMISSION_BINDING", false},
		{"OUT_OF_SCOPE", false},
		{"", true},
		{"", true},
	}
	if len(envelope.Decisions) != len(want) {
		t.Fatalf("decisions = %v", envelope.Decisions)
	}
	for index, item := range envelope.Decisions {
		if item.Decision["granted"] != want[index].granted {
			t.Fatalf("[%d] granted = %v", index, item.Decision)
		}
		if want[index].granted {
			if len(item.Decision) != 4 {
				t.Fatalf("[%d] granted shape = %v", index, item.Decision)
			}
			continue
		}
		if item.Decision["reason"] != want[index].reason || len(item.Decision) != 2 {
			t.Fatalf("[%d] decision = %v, want reason %s with two fields", index, item.Decision, want[index].reason)
		}
	}
}

func TestAuthorizeBatchNotEffective(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	envelope := batchRaw(h, `{
		"effectiveAt":"2025-12-01T00:00:00Z",
		"queries":[
			{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}
		]}`)
	decision := envelope.Decisions[0].Decision
	if decision["granted"] != false || decision["reason"] != "NOT_EFFECTIVE" || len(decision) != 2 {
		t.Fatalf("decision = %v", decision)
	}
}

func TestAuthorizeBatchMatchesSingleAndKeepsOrder(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	triples := []struct{ subject, resource, operation string }{
		{"user-1", "tenant-b/doc-2", "read"},
		{"user-2", "tenant-a/doc-1", "read"},
		{"user-1", "tenant-a/doc-1", "read"},
		{"user-1", "tenant-a/doc-1", "read"},
	}
	rawQueries := ""
	for index, query := range triples {
		if index > 0 {
			rawQueries += ","
		}
		rawQueries += fmt.Sprintf(`{"subject":%q,"resource":%q,"operation":%q}`,
			query.subject, query.resource, query.operation)
	}
	envelope := batchRaw(h, `{"effectiveAt":"2026-02-01T00:00:00Z","queries":[`+rawQueries+`]}`)
	if len(envelope.Decisions) != len(triples) {
		t.Fatalf("decisions = %v", envelope.Decisions)
	}
	for index, query := range triples {
		recorder := h.request(http.MethodPost, "/authorize", map[string]any{
			"subject": query.subject, "resource": query.resource, "operation": query.operation,
			"effectiveAt": "2026-02-01T00:00:00Z",
		})
		h.mustStatus(recorder, http.StatusOK)
		single := mustJSON(t, recorder)["decision"].(map[string]any)
		got := envelope.Decisions[index]
		if got.Subject != query.subject || got.Resource != query.resource || got.Operation != query.operation {
			t.Fatalf("[%d] echo = %v", index, got)
		}
		if fmt.Sprint(got.Decision) != fmt.Sprint(single) {
			t.Fatalf("[%d] batch %v != single %v", index, got.Decision, single)
		}
	}
	// Duplicate triples are not merged and stay in input order.
	if envelope.Decisions[2].Decision != nil &&
		fmt.Sprint(envelope.Decisions[2].Decision) != fmt.Sprint(envelope.Decisions[3].Decision) {
		t.Fatalf("duplicate decisions diverged: %v vs %v",
			envelope.Decisions[2].Decision, envelope.Decisions[3].Decision)
	}
}

func TestAuthorizeBatchDefaultEffectiveAtIsCurrent(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	envelope := batchRaw(h, `{"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	decision := envelope.Decisions[0].Decision
	if decision["granted"] != true {
		t.Fatalf("current-time decision = %v", decision)
	}
	// An explicit null effectiveAt is treated as omitted.
	envelope = batchRaw(h, `{"effectiveAt":null,"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	if envelope.Decisions[0].Decision["granted"] != true {
		t.Fatalf("null effectiveAt decision = %v", envelope.Decisions[0].Decision)
	}
}

func TestAuthorizeBatchEmptyGrantIsNormal(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	envelope := batchRaw(h, `{
		"effectiveAt":"2026-02-01T00:00:00Z",
		"queries":[
			{"subject":"user-2","resource":"tenant-a/doc-1","operation":"read"},
			{"subject":"user-2","resource":"tenant-b/doc-2","operation":"read"}
		]}`)
	if len(envelope.Decisions) != 2 {
		t.Fatalf("decisions = %v", envelope.Decisions)
	}
	for index, item := range envelope.Decisions {
		if item.Decision["granted"] != false || item.Decision["reason"] != "NO_ROLE_BINDING" {
			t.Fatalf("[%d] decision = %v", index, item.Decision)
		}
	}
}

func batchExpectError(t *testing.T, h *apiHarness, body string, wantStatus int, wantType, wantField string) {
	t.Helper()
	recorder := h.raw(http.MethodPost, "/authorize/batch", body)
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), wantStatus)
	}
	errorObject := mustJSON(t, recorder)["error"].(map[string]any)
	field, _ := errorObject["field"].(string)
	if errorObject["type"] != wantType || field != wantField {
		t.Fatalf("error = %v, want type %s field %s", errorObject, wantType, wantField)
	}
	if _, ok := mustJSON(t, recorder)["decisions"]; ok {
		t.Fatalf("error response leaked decisions: %s", recorder.Body.String())
	}
}

func TestAuthorizeBatchStructureErrors(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)
	valid := `{"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`

	batchExpectError(t, h, ``, http.StatusBadRequest, "INVALID_REQUEST", "")
	batchExpectError(t, h, `[]`, http.StatusBadRequest, "INVALID_REQUEST", "")
	batchExpectError(t, h, `null`, http.StatusBadRequest, "INVALID_REQUEST", "")
	batchExpectError(t, h, `{"effectiveAt":"2026-02-01T00:00:00Z"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExpectError(t, h, `{"queries":null}`, http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExpectError(t, h, `{"queries":{}}`, http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExpectError(t, h, `{"queries":"read"}`, http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExpectError(t, h, `{"queries":[]}`, http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExpectError(t, h, `{"queries":[], "effectiveAt":"2026-02-01T00:00:00Z"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExpectError(t, h, `{"queries":[], "effectiveAt":"not-a-time"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExpectError(t, h, `{"queries":[{"subject":"user-1"}],"extra":true}`,
		http.StatusBadRequest, "INVALID_REQUEST", "extra")
	batchExpectError(t, h, strings.Replace(valid, `"queries"`, `"q"`, 1),
		http.StatusBadRequest, "INVALID_REQUEST", "q")

	queries := make([]string, 101)
	for index := range queries {
		queries[index] = `{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}`
	}
	batchExpectError(t, h, `{"queries":[`+strings.Join(queries, ",")+`]}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
}

func TestAuthorizeBatchItemErrors(t *testing.T) {
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
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus := http.StatusBadRequest
			if tc.typ == "NOT_FOUND" {
				wantStatus = http.StatusNotFound
			}
			batchExpectError(t, h, tc.body, wantStatus, tc.typ, tc.fld)
		})
	}
}

func TestAuthorizeBatchTimePriority(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	// Invalid time beats every per-query failure, including grammar and missing members.
	batchExpectError(t, h, `{"effectiveAt":"not-a-time","queries":[
		{"subject":"ghost","resource":"bad r","operation":"read"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	batchExpectError(t, h, `{"effectiveAt":"2026-13-01T00:00:00Z","queries":[
		{"resource":"r"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	batchExpectError(t, h, `{"effectiveAt":7,"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`,
		http.StatusBadRequest, "INVALID_TIME", "effectiveAt")
	// Batch structure still outranks the time check.
	batchExpectError(t, h, `{"effectiveAt":"not-a-time","queries":[]}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	batchExpectError(t, h, `{"effectiveAt":"not-a-time"}`,
		http.StatusBadRequest, "INVALID_REQUEST", "queries")
	// A valid time is shared by the whole batch; timezones normalize to UTC.
	envelope := batchRaw(h, `{
		"effectiveAt":"2026-02-01T08:00:00+08:00",
		"queries":[{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	if envelope.Decisions[0].Decision["granted"] != true {
		t.Fatalf("decision = %v", envelope.Decisions[0].Decision)
	}
}

func TestAuthorizeBatchSingleEntryUnchanged(t *testing.T) {
	h := newHarness(t)
	seedBatchBaseline(h)

	// The existing single entry must remain wired and behave as before.
	recorder := h.request(http.MethodPost, "/authorize", map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
		"effectiveAt": "2026-02-01T00:00:00Z",
	})
	h.mustStatus(recorder, http.StatusOK)
	single := mustJSON(t, recorder)["decision"].(map[string]any)
	envelope := batchRaw(h, `{"effectiveAt":"2026-02-01T00:00:00Z","queries":[
		{"subject":"user-1","resource":"tenant-a/doc-1","operation":"read"}]}`)
	if fmt.Sprint(envelope.Decisions[0].Decision) != fmt.Sprint(single) {
		t.Fatalf("batch %v != single %v", envelope.Decisions[0].Decision, single)
	}

	// The batch explain entry uses the same batch shape as batch authorize;
	// a single-explain body without queries is an INVALID_REQUEST, not a route
	// miss.
	recorder = h.request(http.MethodPost, "/authorize/batch/explain",
		map[string]any{"subject": "user-1"})
	h.mustStatus(recorder, http.StatusBadRequest)
	errorObject := mustJSON(t, recorder)["error"].(map[string]any)
	if errorObject["type"] != "INVALID_REQUEST" || errorObject["field"] != "subject" {
		t.Fatalf("batch/explain error = %v", errorObject)
	}
}
