// Package authz holds the explainable authorization decision logic. It is pure
// Go: callers assemble a Data snapshot from storage and receive stable
// decisions or history events without any database access of their own.
package authz

// Stable reason strings returned by an as-of evaluation. They are part of the
// public contract and must not be renamed.
const (
	// ReasonNoRoleBinding means the subject never has a binding or direct grant
	// covering the requested operation path at any recorded time.
	ReasonNoRoleBinding = "NO_ROLE_BINDING"
	// ReasonNoPermissionBinding means the subject carries a binding/grant, but
	// no role (or direct permission) has a permission point covering the
	// operation on record.
	ReasonNoPermissionBinding = "NO_PERMISSION_BINDING"
	// ReasonOutOfScope means an operation-covering permission exists, but every
	// copy's scope fails to cover the requested resource.
	ReasonOutOfScope = "OUT_OF_SCOPE"
	// ReasonNotEffective means all structurally matching layers exist, but none
	// of their validity intervals is in force at the requested effective time.
	ReasonNotEffective = "NOT_EFFECTIVE"
)

// Scope kinds accepted on stored records.
const (
	ScopeExact  = "exact"
	ScopePrefix = "prefix"
	ScopeAll    = "all"
)

// Close reasons stored on version intervals.
const (
	CloseRevoke = "revoke"
	CloseUpdate = "update"
)

// History event kinds returned by the change-history entry.
const (
	EventGrant  = "GRANT"
	EventUpdate = "UPDATE"
	EventRevoke = "REVOKE"
)

// Scope is one authorization range boundary.
type Scope struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// RoleParent is one inheritance edge: Role inherits from Parent.
type RoleParent struct {
	Role   string
	Parent string
}

// PermissionOperation links a permission point to an operation it covers.
type PermissionOperation struct {
	Permission string
	Operation  string
}

// RoleVersion is one validity window of a subject-role binding with its scope.
type RoleVersion struct {
	Role        string
	Scope       Scope
	From        int64
	To          int64
	HasTo       bool
	CloseReason string
	Seq         int64
}

// GrantVersion is one validity window of a direct permission grant.
type GrantVersion struct {
	Permission  string
	Scope       Scope
	From        int64
	To          int64
	HasTo       bool
	CloseReason string
	Seq         int64
}

// RolePermissionVersion is one validity window of a role-permission point
// authorization.
type RolePermissionVersion struct {
	Role        string
	Permission  string
	From        int64
	To          int64
	HasTo       bool
	CloseReason string
	Seq         int64
}

// Data is the read-only snapshot the temporal evaluator reasons over.
type Data struct {
	RoleVersions           []RoleVersion
	GrantVersions          []GrantVersion
	RolePermissionVersions []RolePermissionVersion
	RoleParents            []RoleParent
	PermissionOperations   []PermissionOperation
}

// Match identifies the single effective layer triple of a granted decision.
type Match struct {
	Role       string `json:"matchedRole,omitempty"`
	Permission string `json:"matchedPermission"`
	Scope      Scope  `json:"matchedScope"`
}

// Decision is the stable result of an as-of evaluation.
type Decision struct {
	Granted bool   `json:"granted"`
	Reason  string `json:"reason,omitempty"`
	Match   *Match `json:"match,omitempty"`
}

// Event is one change-history item ordered by effective time.
type Event struct {
	Event         string `json:"event"`
	OccurredAt    int64  `json:"occurredAt"`
	EffectiveFrom int64  `json:"effectiveFrom"`
	EffectiveTo   *int64 `json:"effectiveTo"`
	Role          string `json:"role,omitempty"`
	Permission    string `json:"permission"`
	Scope         Scope  `json:"scope"`
	Granted       bool   `json:"granted"`
	Seq           int64  `json:"-"`
}
