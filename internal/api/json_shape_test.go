package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestResponseJSONShapes(t *testing.T) {
	h := newHarness(t)
	seedBaseline(h)
	rec := h.request(http.MethodPost, "/authorize", map[string]any{
		"subject": "user-1", "resource": "tenant-a/doc-1", "operation": "read",
	})
	h.mustStatus(rec, http.StatusOK)
	body := rec.Body.String()
	if !strings.Contains(body, `"granted":false`) || strings.Contains(body, "matchedRole") {
		t.Fatalf("denied body leaked match fields: %s", body)
	}
	if strings.Contains(body, `"reason":""`) {
		t.Fatalf("empty reason: %s", body)
	}
}
