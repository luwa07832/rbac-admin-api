// Package authz implements the time-aware authorization model: versioned
// subject/role bindings, role/permission grants and scoped authorizations,
// historical decisions and change history.
package authz

import (
	"time"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// Public error types mirror store.Error so the HTTP layer can render either.
const (
	TypeNotFound       = store.TypeNotFound
	TypeInvalidRequest = store.TypeInvalidRequest
	TypeInvalidTime    = store.TypeInvalidTime
	TypeInvalidRange   = store.TypeInvalidRange
	TypeConflict       = store.TypeConflict
)

// Failure is the structured domain error shared by every abnormal outcome.
type Failure struct {
	Type    string
	Field   string
	Message string
}

func (e *Failure) Error() string { return e.Type + ": " + e.Message }

func failure(typ, field, message string) *Failure {
	return &Failure{Type: typ, Field: field, Message: message}
}

// timeFormat is RFC3339 with nanosecond precision. Every stored and emitted
// timestamp uses this fixed-width UTC layout, so string comparison equals
// chronological comparison.
const timeFormat = "2006-01-02T15:04:05.999999999Z07:00"

// ParseTime accepts an RFC3339 timestamp and returns its canonical UTC text.
// Anything that cannot be parsed (including values outside the supported
// year range) is reported as INVALID_TIME.
func ParseTime(value string) (time.Time, *Failure) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, failure(TypeInvalidTime, "effectiveAt", "time must be an RFC3339 timestamp")
	}
	return parsed, nil
}

// FormatTime renders t as canonical RFC3339Nano UTC text.
func FormatTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

// intervalActive reports whether the half-open interval [from, to) contains t.
// An empty to marks an open interval.
func intervalActive(from, to string, t time.Time) bool {
	at := FormatTime(t)
	if from > at {
		return false
	}
	return to == "" || to > at
}
