package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
)

type authorizeRequestBody struct {
	Subject     string `json:"subject"`
	Resource    string `json:"resource"`
	Operation   string `json:"operation"`
	EffectiveAt string `json:"effectiveAt"`
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
