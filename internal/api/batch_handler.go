package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
)

// maxBatchQueries mirrors authz.MaxBatchQueries at the structural validation
// layer; the service enforces the same bound for direct callers.
const maxBatchQueries = authz.MaxBatchQueries

type batchDecisionItem struct {
	Subject   string `json:"subject"`
	Resource  string `json:"resource"`
	Operation string `json:"operation"`
	Decision  gin.H  `json:"decision"`
}

// authorizeBatchHandler serves POST /authorize/batch. The whole structure and
// shared effectiveAt are validated before any per-query check, and any failure
// returns one error object without partial decisions.
func authorizeBatchHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		effectiveAt, queries, fail := readBatchRequest(c)
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		results, fail := service.BatchDecide(authz.BatchInput{
			EffectiveAtText: effectiveAt,
			Queries:         queries,
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		decisions := make([]batchDecisionItem, len(results))
		for index, result := range results {
			decisions[index] = batchDecisionItem{
				Subject:   result.Subject,
				Resource:  result.Resource,
				Operation: result.Operation,
				Decision:  decisionResponse(result.Decision),
			}
		}
		c.JSON(http.StatusOK, gin.H{"decisions": decisions})
	}
}

type batchExplainItem struct {
	Subject   string              `json:"subject"`
	Resource  string              `json:"resource"`
	Operation string              `json:"operation"`
	Decision  gin.H               `json:"decision"`
	Paths     []authz.SubjectPath `json:"paths"`
}

// authorizeBatchExplainHandler serves POST /authorize/batch/explain. It shares
// the batch structural validation and shared effectiveAt rules with
// /authorize/batch; each entry additionally carries the complete set of
// authorization paths effective at the same moment. Any failure returns one
// error object without partial explanations.
func authorizeBatchExplainHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		effectiveAt, queries, fail := readBatchRequest(c)
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		view, fail := service.BatchExplain(authz.BatchInput{
			EffectiveAtText: effectiveAt,
			Queries:         queries,
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		explanations := make([]batchExplainItem, len(view.Explanations))
		for index, result := range view.Explanations {
			explanations[index] = batchExplainItem{
				Subject:   result.Subject,
				Resource:  result.Resource,
				Operation: result.Operation,
				Decision:  decisionResponse(result.Decision),
				Paths:     result.Paths,
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"effectiveAt":  view.EffectiveAt,
			"explanations": explanations,
		})
	}
}

// readBatchRequest performs the batch-level checks: the body must be one JSON
// object with only effectiveAt and queries, queries must be a non-empty array
// of at most 100 entries, and an effectiveAt that is present and non-null
// must be a string. An invalid effectiveAt string outranks every per-query
// check and is reported as INVALID_TIME by the service.
func readBatchRequest(c *gin.Context) (*string, []json.RawMessage, *authz.Failure) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, nil, &authz.Failure{Type: authz.TypeInvalidRequest, Message: "request body is missing or too large"}
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(raw), &fields); err != nil {
		return nil, nil, &authz.Failure{Type: authz.TypeInvalidRequest, Message: "request body is not valid JSON for this entry"}
	}
	if fields == nil {
		return nil, nil, &authz.Failure{Type: authz.TypeInvalidRequest, Message: "request body must be a JSON object"}
	}

	names := make([]string, 0, len(fields))
	for name := range fields {
		if name != "effectiveAt" && name != "queries" {
			names = append(names, name)
		}
	}
	if len(names) > 0 {
		sort.Strings(names)
		return nil, nil, &authz.Failure{Type: authz.TypeInvalidRequest, Field: names[0], Message: "unknown field " + names[0]}
	}

	rawQueries, present := fields["queries"]
	if !present {
		return nil, nil, &authz.Failure{Type: authz.TypeInvalidRequest, Field: "queries", Message: "field queries is required"}
	}
	var queries []json.RawMessage
	if err := json.Unmarshal(rawQueries, &queries); err != nil {
		return nil, nil, &authz.Failure{Type: authz.TypeInvalidRequest, Field: "queries", Message: "field queries must be an array"}
	}
	if len(queries) == 0 {
		return nil, nil, &authz.Failure{Type: authz.TypeInvalidRequest, Field: "queries", Message: "field queries must contain at least one entry"}
	}
	if len(queries) > maxBatchQueries {
		return nil, nil, &authz.Failure{Type: authz.TypeInvalidRequest, Field: "queries", Message: "field queries must contain at most 100 entries"}
	}

	var effectiveAt *string
	if rawEffectiveAt, ok := fields["effectiveAt"]; ok {
		if string(bytes.TrimSpace(rawEffectiveAt)) != "null" {
			var text string
			if err := json.Unmarshal(rawEffectiveAt, &text); err != nil {
				return nil, nil, &authz.Failure{Type: authz.TypeInvalidTime, Field: "effectiveAt", Message: "time must be an RFC3339 timestamp"}
			}
			effectiveAt = &text
		}
	}
	return effectiveAt, queries, nil
}
