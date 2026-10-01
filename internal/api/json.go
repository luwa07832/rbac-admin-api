package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
)

// readJSON reads a JSON object body with strict unknown-field and type
// checking. An empty body is allowed when optional is true (timing-only writes
// default every field to its zero value).
func readJSON(c *gin.Context, target any, optional bool) *authz.Failure {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return &authz.Failure{Type: authz.TypeInvalidRequest, Message: "request body is missing or too large"}
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		if optional {
			return nil
		}
		return &authz.Failure{Type: authz.TypeInvalidRequest, Message: "request body is empty"}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if _, ok := err.(*json.UnmarshalTypeError); ok {
			return &authz.Failure{Type: authz.TypeInvalidRequest, Message: fmt.Sprintf("request body field has the wrong type: %v", err)}
		}
		return &authz.Failure{Type: authz.TypeInvalidRequest, Message: "request body is not valid JSON for this entry"}
	}
	if decoder.More() {
		return &authz.Failure{Type: authz.TypeInvalidRequest, Message: "request body contains more than one JSON value"}
	}
	return nil
}

func writeFailure(c *gin.Context, fail *authz.Failure) {
	if fail == nil {
		return
	}
	status := http.StatusBadRequest
	switch fail.Type {
	case authz.TypeNotFound:
		status = http.StatusNotFound
	case authz.TypeConflict:
		status = http.StatusConflict
	}
	errorObject := gin.H{"type": fail.Type, "message": fail.Message}
	if fail.Field != "" {
		errorObject["field"] = fail.Field
	}
	c.JSON(status, gin.H{"error": errorObject})
}
