package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	maxIdentifierLen = 256
	maxNameLen       = 256
	maxBodyBytes     = 1 << 20
)

// validIdentifier enforces the public identifier contract: present, bounded,
// no surrounding whitespace and no control characters.
func validIdentifier(value string) bool {
	if value == "" || len(value) > maxIdentifierLen {
		return false
	}
	if strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r == 0x7f || r < 0x20 {
			return false
		}
	}
	return true
}

func validName(value string) bool {
	if len(value) > maxNameLen {
		return false
	}
	for _, r := range value {
		if r == 0x7f || r < 0x20 {
			return false
		}
	}
	return true
}

// decisionRequest is the accepted public shape for both the authorize and the
// change-history entry. EffectiveAt and the range ends are optional.
type decisionRequest struct {
	Subject   string
	Resource  string
	Operation string

	HasEffectiveAt bool
	EffectiveAt    time.Time

	HasRangeFrom bool
	RangeFrom    time.Time
	HasRangeTo   bool
	RangeTo      time.Time
}

var (
	errBodyInvalid = errors.New("request body is not a valid decision request")
	errInvalidTime = errors.New("time value is not a valid RFC3339 timestamp")
)

// queryField describes one accepted temporal-query key.
type queryField struct {
	name   string
	apply  func(*decisionRequest, time.Time)
	hasRaw func(decisionRequest) bool
}

var timeFields = map[string]func(*decisionRequest, time.Time){
	"effectiveAt": func(r *decisionRequest, t time.Time) {
		r.HasEffectiveAt = true
		r.EffectiveAt = t
	},
	"from": func(r *decisionRequest, t time.Time) {
		r.HasRangeFrom = true
		r.RangeFrom = t
	},
	"effectiveFrom": func(r *decisionRequest, t time.Time) {
		r.HasRangeFrom = true
		r.RangeFrom = t
	},
	"to": func(r *decisionRequest, t time.Time) {
		r.HasRangeTo = true
		r.RangeTo = t
	},
	"effectiveTo": func(r *decisionRequest, t time.Time) {
		r.HasRangeTo = true
		r.RangeTo = t
	},
}

// rangeAlias pairs the short and long range key spellings.
var rangeAlias = map[string]string{
	"from":          "effectiveFrom",
	"effectiveFrom": "from",
	"to":            "effectiveTo",
	"effectiveTo":   "to",
}

func parseRFC3339(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, value)
}

func applyField(request *decisionRequest, key, value string) error {
	switch key {
	case "subject":
		request.Subject = value
	case "resource":
		request.Resource = value
	case "operation":
		request.Operation = value
	default:
		parsed, err := parseRFC3339(value)
		if err != nil {
			return errInvalidTime
		}
		timeFields[key](request, parsed)
	}
	return nil
}

// decodeDecisionJSON parses a decision body strictly: the top level must be an
// object, every value a string, duplicate and unknown keys are rejected, and
// the subject/resource/operation triple is mandatory.
func decodeDecisionJSON(body []byte) (decisionRequest, error) {
	var request decisionRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		return request, errBodyInvalid
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return request, errBodyInvalid
	}

	seen := map[string]bool{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return request, errBodyInvalid
		}
		key, ok := keyToken.(string)
		if !ok {
			return request, errBodyInvalid
		}
		if _, accepted := acceptedField(key); !accepted || seen[key] {
			return request, errBodyInvalid
		}
		if alias := rangeAlias[key]; seen[alias] {
			return request, errBodyInvalid
		}
		seen[key] = true

		valueToken, err := decoder.Token()
		if err != nil {
			return request, errBodyInvalid
		}
		value, ok := valueToken.(string)
		if !ok {
			return request, errBodyInvalid
		}
		if err := applyField(&request, key, value); err != nil {
			return request, err
		}
	}

	closing, err := decoder.Token()
	if err != nil {
		return request, errBodyInvalid
	}
	if closingDelim, ok := closing.(json.Delim); !ok || closingDelim != '}' {
		return request, errBodyInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return request, errBodyInvalid
	}
	if !seen["subject"] || !seen["resource"] || !seen["operation"] {
		return request, errBodyInvalid
	}
	return request, nil
}

func acceptedField(key string) (struct{}, bool) {
	switch key {
	case "subject", "resource", "operation", "effectiveAt",
		"from", "to", "effectiveFrom", "effectiveTo":
		return struct{}{}, true
	}
	return struct{}{}, false
}

// parseDecisionQuery accepts the same fields as query parameters. Duplicate
// parameters, unknown parameters and empty values make the request invalid.
func parseDecisionQuery(rawQuery string) (decisionRequest, error) {
	var request decisionRequest
	if rawQuery == "" {
		return request, errBodyInvalid
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(rawQuery, "&") {
		key, rawValue, found := strings.Cut(part, "=")
		if !found {
			return request, errBodyInvalid
		}
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			return request, errBodyInvalid
		}
		if _, accepted := acceptedField(decodedKey); !accepted || seen[decodedKey] {
			return request, errBodyInvalid
		}
		if alias := rangeAlias[decodedKey]; seen[alias] {
			return request, errBodyInvalid
		}
		seen[decodedKey] = true

		decodedValue, err := url.QueryUnescape(rawValue)
		if err != nil {
			return request, errBodyInvalid
		}
		if decodedValue == "" {
			return request, errBodyInvalid
		}
		if err := applyField(&request, decodedKey, decodedValue); err != nil {
			return request, err
		}
	}
	if !seen["subject"] || !seen["resource"] || !seen["operation"] {
		return request, errBodyInvalid
	}
	return request, nil
}

// decodeStrictJSON decodes body into target while rejecting unknown fields and
// trailing data. An empty body is allowed so callers can omit optional fields.
func decodeStrictJSON(body []byte, target any) error {
	if len(body) > maxBodyBytes {
		return errBodyInvalid
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errBodyInvalid
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errBodyInvalid
	}
	return nil
}
