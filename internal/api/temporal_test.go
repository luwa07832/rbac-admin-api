package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

func newTemporalRouter(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "temporal.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRouter(st), st
}

func fixedClock(st *store.Store, ts string) {
	when, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic(err)
	}
	st.SetClock(func() time.Time { return when })
}

func doRequest(t *testing.T, handler http.Handler, method, target string, bodyParts ...string) (int, map[string]any) {
	body := ""
	if len(bodyParts) > 0 {
		body = bodyParts[0]
	}
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var parsed map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("non-json %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, parsed
}

func mustStatus(t *testing.T, got int, want int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("status = %d, want %d: %v", got, want, body)
	}
}

func seedTemporal(t *testing.T, handler http.Handler) {
	t.Helper()
	create := func(plural, id string) {
		status, body := doRequest(t, handler, http.MethodPost, "/api/v1/"+plural,
			`{"id":"`+id+`","name":"`+id+`"}`)
		mustStatus(t, status, http.StatusCreated, body)
	}
	create("subjects", "alice")
	create("resources", "doc")
	create("operations", "read")
	create("permissions", "p1")
	create("roles", "r1")
	status, body := doRequest(t, handler, http.MethodPost,
		"/api/v1/permissions/p1/operations", `{"id":"read"}`)
	mustStatus(t, status, http.StatusNoContent, body)
}

func TestAuthorizeEffectiveAtLifecycle(t *testing.T) {
	handler, st := newTemporalRouter(t)
	seedTemporal(t, handler)
	fixedClock(st, "2025-03-01T00:00:00Z")

	// Authorize the permission for the role and bind at this instant.
	status, body := doRequest(t, handler, http.MethodPost,
		"/api/v1/roles/r1/permissions", `{"id":"p1"}`)
	mustStatus(t, status, http.StatusNoContent, body)
	status, body = doRequest(t, handler, http.MethodPost,
		"/api/v1/subjects/alice/roles",
		`{"role":"r1","scope":{"kind":"exact","value":"doc"}}`)
	mustStatus(t, status, http.StatusNoContent, body)

	// Before the change nothing is effective.
	status, body = doRequest(t, handler, http.MethodGet,
		"/api/v1/authorize?subject=alice&resource=doc&operation=read&effectiveAt=2025-01-01T00:00:00Z")
	mustStatus(t, status, http.StatusOK, body)
	if body["granted"] != false || body["reason"] != "NOT_EFFECTIVE" {
		t.Fatalf("past decision = %v", body)
	}
	if _, present := body["matchedRole"]; present {
		t.Fatalf("denial must not carry matched fields: %v", body)
	}

	// At the change instant the triple is granted.
	status, body = doRequest(t, handler, http.MethodGet,
		"/api/v1/authorize?subject=alice&resource=doc&operation=read&effectiveAt=2025-03-01T00:00:01Z")
	mustStatus(t, status, http.StatusOK, body)
	if body["granted"] != true {
		t.Fatalf("granted decision = %v", body)
	}
	if body["matchedRole"] != "r1" || body["matchedPermission"] != "p1" {
		t.Fatalf("match fields = %v", body)
	}
	scope := body["matchedScope"].(map[string]any)
	if scope["kind"] != "exact" || scope["value"] != "doc" {
		t.Fatalf("matchedScope = %v", scope)
	}
	if _, present := body["reason"]; present {
		t.Fatalf("grant must not carry a reason: %v", body)
	}
}

func TestAuthorizeTypedErrors(t *testing.T) {
	handler, _ := newTemporalRouter(t)
	seedTemporal(t, handler)

	status, body := doRequest(t, handler, http.MethodGet,
		"/api/v1/authorize?subject=ghost&resource=doc&operation=read")
	mustStatus(t, status, http.StatusNotFound, body)
	errBody := body["error"].(map[string]any)
	if errBody["type"] != "NOT_FOUND" || errBody["field"] != "subject" {
		t.Fatalf("subject error = %v", errBody)
	}

	status, body = doRequest(t, handler, http.MethodGet,
		"/api/v1/authorize?subject=alice&resource=ghost&operation=read")
	mustStatus(t, status, http.StatusNotFound, body)
	if body["error"].(map[string]any)["field"] != "resource" {
		t.Fatalf("resource error = %v", body["error"])
	}

	status, body = doRequest(t, handler, http.MethodGet,
		"/api/v1/authorize?subject=alice&resource=doc&operation=ghost")
	mustStatus(t, status, http.StatusNotFound, body)
	if body["error"].(map[string]any)["field"] != "operation" {
		t.Fatalf("operation error = %v", body["error"])
	}

	status, body = doRequest(t, handler, http.MethodGet,
		"/api/v1/authorize?subject=alice&resource=doc&operation=read&effectiveAt=nope")
	mustStatus(t, status, http.StatusBadRequest, body)
	if body["error"].(map[string]any)["type"] != "INVALID_TIME" {
		t.Fatalf("bad time error = %v", body["error"])
	}

	status, body = doRequest(t, handler, http.MethodGet,
		"/api/v1/authorize?subject=alice&resource=doc&operation=read&effectiveAt=9999-01-01T00:00:00Z")
	mustStatus(t, status, http.StatusBadRequest, body)
	if body["error"].(map[string]any)["type"] != "INVALID_TIME" {
		t.Fatalf("out of range error = %v", body["error"])
	}
}

func TestAuthorizeDefaultKeepsCurrentSemantics(t *testing.T) {
	handler, st := newTemporalRouter(t)
	seedTemporal(t, handler)
	fixedClock(st, "2025-03-01T00:00:00Z")
	_, _ = doRequest(t, handler, http.MethodPost, "/api/v1/roles/r1/permissions", `{"id":"p1"}`)
	_, _ = doRequest(t, handler, http.MethodPost, "/api/v1/subjects/alice/roles",
		`{"role":"r1","scope":{"kind":"exact","value":"doc"}}`)

	status, body := doRequest(t, handler, http.MethodGet,
		"/api/v1/authorize?subject=alice&resource=doc&operation=read")
	mustStatus(t, status, http.StatusOK, body)
	if body["granted"] != true {
		t.Fatalf("default decision = %v", body)
	}
	if _, present := body["effectiveAt"]; present {
		t.Fatalf("effectiveAt must only appear when supplied: %v", body)
	}
}

func TestHistoryReturnsOrderedEvents(t *testing.T) {
	handler, st := newTemporalRouter(t)
	seedTemporal(t, handler)
	fixedClock(st, "2025-03-01T00:00:00Z")
	_, _ = doRequest(t, handler, http.MethodPost, "/api/v1/roles/r1/permissions", `{"id":"p1"}`)
	_, _ = doRequest(t, handler, http.MethodPost, "/api/v1/subjects/alice/roles",
		`{"role":"r1","scope":{"kind":"exact","value":"doc"}}`)
	fixedClock(st, "2025-04-01T00:00:00Z")
	_, _ = doRequest(t, handler, http.MethodDelete,
		"/api/v1/subjects/alice/roles/r1?scope_kind=exact&scope_value=doc", "")

	status, body := doRequest(t, handler, http.MethodGet,
		"/api/v1/history?subject=alice&resource=doc&operation=read")
	mustStatus(t, status, http.StatusOK, body)
	events, ok := body["events"].([]any)
	if !ok || len(events) != 2 {
		t.Fatalf("events = %v", body["events"])
	}
	first := events[0].(map[string]any)
	second := events[1].(map[string]any)
	if first["event"] != "GRANT" || first["granted"] != true {
		t.Fatalf("first = %v", first)
	}
	if second["event"] != "REVOKE" || second["granted"] != false {
		t.Fatalf("second = %v", second)
	}
	for _, key := range []string{"event", "occurredAt", "effectiveFrom", "effectiveTo",
		"role", "permission", "scope", "granted"} {
		if _, present := first[key]; !present {
			t.Fatalf("event missing %s: %v", key, first)
		}
	}
}

func TestHistoryEmptyAndInvalidRange(t *testing.T) {
	handler, _ := newTemporalRouter(t)
	seedTemporal(t, handler)

	status, body := doRequest(t, handler, http.MethodGet,
		"/api/v1/history?subject=alice&resource=doc&operation=read")
	mustStatus(t, status, http.StatusOK, body)
	if items, ok := body["events"].([]any); !ok || len(items) != 0 {
		t.Fatalf("events = %v, want empty list", body["events"])
	}

	status, body = doRequest(t, handler, http.MethodGet,
		"/api/v1/history?subject=alice&resource=doc&operation=read&from=2025-02-01T00:00:00Z&to=2025-01-01T00:00:00Z")
	mustStatus(t, status, http.StatusBadRequest, body)
	if body["error"].(map[string]any)["type"] != "INVALID_RANGE" {
		t.Fatalf("range error = %v", body["error"])
	}
}
