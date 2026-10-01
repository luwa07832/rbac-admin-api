package api

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// supportedInstant bounds accepted RFC3339 values to timestamps the service can
// store and compare deterministically. Everything parseable stays inside a few
// centuries of the Unix epoch in nanosecond resolution.
func supportedInstant(t time.Time) bool {
	year := t.UTC().Year()
	return year >= 1900 && year <= 2300
}

// readDecisionRequest parses one GET or POST temporal query. The returned
// status-relevant error is nil, errBodyInvalid or errInvalidTime.
func readDecisionRequest(c *gin.Context) (decisionRequest, error) {
	switch c.Request.Method {
	case http.MethodGet:
		if c.Request.ContentLength > 0 {
			return decisionRequest{}, errBodyInvalid
		}
		return parseDecisionQuery(c.Request.URL.RawQuery)
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodyBytes+1))
		if err != nil || len(body) > maxBodyBytes {
			return decisionRequest{}, errBodyInvalid
		}
		return decodeDecisionJSON(body)
	default:
		return decisionRequest{}, errBodyInvalid
	}
}

// respondTypedError renders the temporal-query error envelope: type names the
// failure class and field names the offending input when one applies.
func respondTypedError(c *gin.Context, status int, typ, field, message string) {
	payload := gin.H{"type": typ, "message": message}
	if field != "" {
		payload["field"] = field
	}
	c.AbortWithStatusJSON(status, gin.H{"error": payload})
}

// ensureReferenced checks existence in the published order subject, resource,
// operation so an unknown input is never reported as a denial.
func ensureReferenced(c *gin.Context, st *store.Store, request decisionRequest) bool {
	exists, err := st.Exists(store.KindSubject, request.Subject)
	if err != nil {
		respondStorageError(c)
		return false
	}
	if !exists {
		respondTypedError(c, http.StatusNotFound, "NOT_FOUND", "subject",
			"the subject does not exist")
		return false
	}
	exists, err = st.Exists(store.KindResource, request.Resource)
	if err != nil {
		respondStorageError(c)
		return false
	}
	if !exists {
		respondTypedError(c, http.StatusNotFound, "NOT_FOUND", "resource",
			"the resource does not exist")
		return false
	}
	exists, err = st.Exists(store.KindOperation, request.Operation)
	if err != nil {
		respondStorageError(c)
		return false
	}
	if !exists {
		respondTypedError(c, http.StatusNotFound, "NOT_FOUND", "operation",
			"the operation does not exist")
		return false
	}
	return true
}

// validateQueryRequest performs the shared parse, time and range checks and
// writes the published error response when something fails.
func validateQueryRequest(c *gin.Context, withRange bool) (decisionRequest, bool) {
	request, err := readDecisionRequest(c)
	if errors.Is(err, errInvalidTime) {
		respondTypedError(c, http.StatusBadRequest, "INVALID_TIME", "",
			"time values must use RFC3339 format within the supported range")
		return request, false
	}
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid_request",
			"request must describe one subject, resource and operation")
		return request, false
	}
	if !validIdentifier(request.Subject) || !validIdentifier(request.Resource) ||
		!validIdentifier(request.Operation) {
		respondError(c, http.StatusBadRequest, "invalid_request",
			"subject, resource and operation must be valid identifiers")
		return request, false
	}
	if request.HasEffectiveAt && !supportedInstant(request.EffectiveAt) {
		respondTypedError(c, http.StatusBadRequest, "INVALID_TIME", "effectiveAt",
			"the effectiveAt value is outside the supported range")
		return request, false
	}
	if withRange {
		if request.HasEffectiveAt {
			respondError(c, http.StatusBadRequest, "invalid_request",
				"the history entry accepts a time range, not effectiveAt")
			return request, false
		}
		if (request.HasRangeFrom && !supportedInstant(request.RangeFrom)) ||
			(request.HasRangeTo && !supportedInstant(request.RangeTo)) {
			respondTypedError(c, http.StatusBadRequest, "INVALID_TIME", "",
				"the time range must stay within the supported range")
			return request, false
		}
		if request.HasRangeFrom && request.HasRangeTo &&
			request.RangeFrom.UnixNano() > request.RangeTo.UnixNano() {
			respondTypedError(c, http.StatusBadRequest, "INVALID_RANGE", "",
				"the range start must not be later than the range end")
			return request, false
		}
	} else if request.HasRangeFrom || request.HasRangeTo {
		respondError(c, http.StatusBadRequest, "invalid_request",
			"the authorize entry does not accept a time range")
		return request, false
	}
	return request, true
}

// handleAuthorize is the temporal explainable decision entry. Every decided
// outcome answers 200; malformed input, unknown references and bad time values
// use the published error statuses.
func handleAuthorize(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		request, ok := validateQueryRequest(c, false)
		if !ok {
			return
		}
		if !ensureReferenced(c, st, request) {
			return
		}

		data, err := st.Snapshot(request.Subject)
		if err != nil {
			respondStorageError(c)
			return
		}
		instant := time.Now().UTC().UnixNano()
		if request.HasEffectiveAt {
			instant = request.EffectiveAt.UnixNano()
		}
		decision := authz.EvaluateAt(authz.Input{
			Subject:   request.Subject,
			Resource:  request.Resource,
			Operation: request.Operation,
		}, data, instant)

		response := gin.H{
			"subject":   request.Subject,
			"resource":  request.Resource,
			"operation": request.Operation,
			"granted":   decision.Granted,
		}
		if request.HasEffectiveAt {
			response["effectiveAt"] = request.EffectiveAt.UTC().Format(time.RFC3339Nano)
		}
		if decision.Granted {
			response["matchedRole"] = matchedRole(decision.Match)
			response["matchedPermission"] = decision.Match.Permission
			response["matchedScope"] = decision.Match.Scope
		} else {
			response["reason"] = decision.Reason
		}
		c.JSON(http.StatusOK, response)
	}
}

func matchedRole(match *authz.Match) any {
	if match == nil || match.Role == "" {
		return nil
	}
	return match.Role
}

// handleHistory is the change-history entry. It returns every effective change
// for one triple, oldest first; an empty result is an empty list.
func handleHistory(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		request, ok := validateQueryRequest(c, true)
		if !ok {
			return
		}
		if !ensureReferenced(c, st, request) {
			return
		}

		data, err := st.Snapshot(request.Subject)
		if err != nil {
			respondStorageError(c)
			return
		}
		historyRange := authz.HistoryRange{}
		if request.HasRangeFrom {
			historyRange.HasFrom = true
			historyRange.From = request.RangeFrom.UnixNano()
		}
		if request.HasRangeTo {
			historyRange.HasTo = true
			historyRange.To = request.RangeTo.UnixNano()
		}
		events := authz.Timeline(authz.Input{
			Subject:   request.Subject,
			Resource:  request.Resource,
			Operation: request.Operation,
		}, data, historyRange)

		items := make([]gin.H, 0, len(events))
		for _, event := range events {
			item := gin.H{
				"event":         event.Event,
				"occurredAt":    formatInstant(event.OccurredAt),
				"effectiveFrom": formatInstant(event.EffectiveFrom),
				"role":          emptyAsNil(event.Role),
				"permission":    event.Permission,
				"scope":         event.Scope,
				"granted":       event.Granted,
			}
			if event.EffectiveTo != nil {
				item["effectiveTo"] = formatInstant(*event.EffectiveTo)
			} else {
				item["effectiveTo"] = nil
			}
			items = append(items, item)
		}
		c.JSON(http.StatusOK, gin.H{"events": items})
	}
}

func emptyAsNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func formatInstant(nanos int64) string {
	return time.Unix(0, nanos).UTC().Format(time.RFC3339Nano)
}
