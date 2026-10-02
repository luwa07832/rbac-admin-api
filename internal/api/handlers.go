package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
)

type authorizeRequestBody struct {
	Subject     string `json:"subject"`
	Resource    string `json:"resource"`
	Operation   string `json:"operation"`
	EffectiveAt string `json:"effectiveAt"`
}

type authorizeBatchRequestBody struct {
	EffectiveAt json.RawMessage `json:"effectiveAt"`
	Queries     json.RawMessage `json:"queries"`
}

type authorizeBatchQueryRequestBody struct {
	Subject   string `json:"subject"`
	Resource  string `json:"resource"`
	Operation string `json:"operation"`
}

func authorizeHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body authorizeRequestBody
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		decision, fail := service.Decide(authz.DecisionInput{
			Subject:     body.Subject,
			Resource:    body.Resource,
			Operation:   body.Operation,
			EffectiveAt: body.EffectiveAt,
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"decision": decisionResponse(decision)})
	}
}

func authorizeBatchHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body authorizeBatchRequestBody
		if fail := readStrictJSONObject(c, &body); fail != nil {
			writeFailure(c, fail)
			return
		}

		effectiveAt := ""
		if len(body.EffectiveAt) > 0 {
			if fail := decodeStrictJSON(body.EffectiveAt, &effectiveAt, "effectiveAt"); fail != nil {
				writeFailure(c, &authz.Failure{
					Type:    authz.TypeInvalidTime,
					Field:   "effectiveAt",
					Message: "time must be an RFC3339 timestamp",
				})
				return
			}
			_, timeFail := authz.ParseTime(effectiveAt)
			if timeFail != nil {
				writeFailure(c, timeFail)
				return
			}
		}
		var rawQueries []json.RawMessage
		if fail := decodeStrictJSON(body.Queries, &rawQueries, "queries"); fail != nil {
			writeFailure(c, fail)
			return
		}
		if len(rawQueries) == 0 || len(rawQueries) > 100 {
			writeFailure(c, &authz.Failure{
				Type:    authz.TypeInvalidRequest,
				Field:   "queries",
				Message: "queries must contain between 1 and 100 items",
			})
			return
		}

		queries := make([]authz.BatchDecisionQuery, len(rawQueries))
		for index, rawQuery := range rawQueries {
			var query authorizeBatchQueryRequestBody
			prefix := "queries[" + jsonIndex(index) + "]."
			if bytes.Equal(bytes.TrimSpace(rawQuery), []byte("null")) {
				writeFailure(c, &authz.Failure{
					Type:    authz.TypeInvalidRequest,
					Field:   "queries[" + jsonIndex(index) + "]",
					Message: "queries item must be a JSON object",
				})
				return
			}
			if fail := decodeStrictJSON(rawQuery, &query, prefix); fail != nil {
				writeFailure(c, fail)
				return
			}
			queries[index] = authz.BatchDecisionQuery{
				Subject:   query.Subject,
				Resource:  query.Resource,
				Operation: query.Operation,
			}
		}

		results, fail := service.DecideBatch(authz.BatchDecisionInput{
			EffectiveAt: effectiveAt,
			Queries:     queries,
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}

		decisions := make([]gin.H, 0, len(results))
		for _, result := range results {
			item := gin.H{
				"subject":   result.Query.Subject,
				"resource":  result.Query.Resource,
				"operation": result.Query.Operation,
			}
			for key, value := range decisionResponse(result.Decision) {
				item[key] = value
			}
			decisions = append(decisions, item)
		}
		c.JSON(http.StatusOK, gin.H{"decisions": decisions})
	}
}

func jsonIndex(index int) string {
	return strconv.Itoa(index)
}

func authorizeExplainHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body authorizeRequestBody
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		view, fail := service.Explain(authz.DecisionInput{
			Subject:     body.Subject,
			Resource:    body.Resource,
			Operation:   body.Operation,
			EffectiveAt: body.EffectiveAt,
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"effectiveAt": view.EffectiveAt,
			"decision":    decisionResponse(view.Decision),
			"paths":       view.Paths,
		})
	}
}

func decisionResponse(decision *authz.Decision) gin.H {
	if decision.Granted {
		return gin.H{
			"granted":           true,
			"matchedRole":       nullableJSON(decision.Match.Role),
			"matchedPermission": nullableJSON(decision.Match.Permission),
			"matchedScope":      decision.Match.Scope,
		}
	}
	return gin.H{"granted": false, "reason": decision.Reason}
}

func nullableJSON(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func accessHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		items, fail := service.Access(authz.AccessInput{
			Subject:     pathParam(c, "id"),
			EffectiveAt: c.Query("effectiveAt"),
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"access": items})
	}
}

func accessDiffHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		view, fail := service.AccessDiff(authz.AccessDiffInput{
			Subject: pathParam(c, "id"),
			From:    c.Query("from"),
			To:      c.Query("to"),
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, view)
	}
}

func rolePermissionsHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		view, fail := service.RolePermissions(authz.RolePermissionsInput{
			Role:        pathParam(c, "role"),
			EffectiveAt: c.Query("effectiveAt"),
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, view)
	}
}

func resourceSubjectsHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		view, fail := service.ResourceSubjects(authz.ResourceSubjectsInput{
			Resource:    pathParam(c, "resource"),
			Operation:   c.Query("operation"),
			EffectiveAt: c.Query("effectiveAt"),
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, view)
	}
}

func resourceSubjectsDiffHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		view, fail := service.ResourceSubjectsDiff(authz.ResourceSubjectsDiffInput{
			Resource:  pathParam(c, "resource"),
			Operation: c.Query("operation"),
			From:      c.Query("from"),
			To:        c.Query("to"),
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, view)
	}
}

func historyHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject := c.Query("subject")
		resource := c.Query("resource")
		operation := c.Query("operation")
		if subject == "" || resource == "" || operation == "" {
			writeFailure(c, &authz.Failure{
				Type:    authz.TypeInvalidRequest,
				Field:   "subject",
				Message: "subject, resource and operation query parameters are required",
			})
			return
		}
		events, fail := service.History(authz.HistoryInput{
			Subject:   subject,
			Resource:  resource,
			Operation: operation,
			From:      c.Query("from"),
			To:        c.Query("to"),
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"events": events})
	}
}
