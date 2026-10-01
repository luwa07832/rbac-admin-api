package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
)

type timingRequest struct {
	OccurredAt    string `json:"occurredAt"`
	EffectiveFrom string `json:"effectiveFrom"`
}

type roleParentsRequest struct {
	Parents []string `json:"parents"`
}

type permissionOperationsRequest struct {
	Operations []string `json:"operations"`
}

type scopeRequest struct {
	Role          string `json:"role"`
	Permission    string `json:"permission"`
	Scope         string `json:"scope"`
	OccurredAt    string `json:"occurredAt"`
	EffectiveFrom string `json:"effectiveFrom"`
}

type bindingUpdateRequest struct {
	NewRole       string `json:"newRole"`
	OccurredAt    string `json:"occurredAt"`
	EffectiveFrom string `json:"effectiveFrom"`
}

type rolePermissionUpdateRequest struct {
	NewRole       string `json:"newRole"`
	NewPermission string `json:"newPermission"`
	OccurredAt    string `json:"occurredAt"`
	EffectiveFrom string `json:"effectiveFrom"`
}

type scopeUpdateRequest struct {
	Role          string `json:"role"`
	Permission    string `json:"permission"`
	Scope         string `json:"scope"`
	NewRole       string `json:"newRole"`
	NewPermission string `json:"newPermission"`
	NewScope      string `json:"newScope"`
	OccurredAt    string `json:"occurredAt"`
	EffectiveFrom string `json:"effectiveFrom"`
}

func setRoleParentsHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body roleParentsRequest
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.SetRoleParents(authz.SetRoleParentsInput{
			RoleID: pathParam(c, "id"), Parents: body.Parents,
		}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"updated": true})
	}
}

func setPermissionOperationsHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body permissionOperationsRequest
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.SetPermissionOperations(authz.SetPermissionOperationsInput{
			PermissionID: pathParam(c, "id"), Operations: body.Operations,
		}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"updated": true})
	}
}

func grantBindingHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body timingRequest
		if fail := readJSON(c, &body, true); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.GrantBinding(authz.LayerWrite{
			Subject:       pathParam(c, "id"),
			Role:          pathParam(c, "role"),
			OccurredAt:    body.OccurredAt,
			EffectiveFrom: body.EffectiveFrom,
		}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "GRANT"})
	}
}

func updateBindingHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body bindingUpdateRequest
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.UpdateBinding(
			authz.LayerWrite{
				Subject:       pathParam(c, "id"),
				Role:          pathParam(c, "role"),
				OccurredAt:    body.OccurredAt,
				EffectiveFrom: body.EffectiveFrom,
			},
			authz.LayerWrite{Role: body.NewRole},
		); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "UPDATE"})
	}
}

func revokeBindingHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body timingRequest
		if fail := readJSON(c, &body, true); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.RevokeBinding(authz.LayerWrite{
			Subject:       pathParam(c, "id"),
			Role:          pathParam(c, "role"),
			OccurredAt:    body.OccurredAt,
			EffectiveFrom: body.EffectiveFrom,
		}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "REVOKE"})
	}
}

func grantRolePermissionHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body timingRequest
		if fail := readJSON(c, &body, true); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.GrantRolePermission(authz.LayerWrite{
			Role:          pathParam(c, "id"),
			Permission:    pathParam(c, "perm"),
			OccurredAt:    body.OccurredAt,
			EffectiveFrom: body.EffectiveFrom,
		}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "GRANT"})
	}
}

func updateRolePermissionHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body rolePermissionUpdateRequest
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.UpdateRolePermission(
			authz.LayerWrite{
				Role:          pathParam(c, "id"),
				Permission:    pathParam(c, "perm"),
				OccurredAt:    body.OccurredAt,
				EffectiveFrom: body.EffectiveFrom,
			},
			authz.LayerWrite{Role: body.NewRole, Permission: body.NewPermission},
		); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "UPDATE"})
	}
}

func revokeRolePermissionHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body timingRequest
		if fail := readJSON(c, &body, true); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.RevokeRolePermission(authz.LayerWrite{
			Role:          pathParam(c, "id"),
			Permission:    pathParam(c, "perm"),
			OccurredAt:    body.OccurredAt,
			EffectiveFrom: body.EffectiveFrom,
		}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "REVOKE"})
	}
}

func grantScopeHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body scopeRequest
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.GrantScope(authz.LayerWrite{
			Subject:       pathParam(c, "id"),
			Role:          body.Role,
			Permission:    body.Permission,
			Scope:         body.Scope,
			OccurredAt:    body.OccurredAt,
			EffectiveFrom: body.EffectiveFrom,
		}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "GRANT"})
	}
}

func updateScopeHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body scopeUpdateRequest
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.UpdateScope(
			authz.LayerWrite{
				Subject:       pathParam(c, "id"),
				Role:          body.Role,
				Permission:    body.Permission,
				Scope:         body.Scope,
				OccurredAt:    body.OccurredAt,
				EffectiveFrom: body.EffectiveFrom,
			},
			authz.LayerWrite{
				Role:       body.NewRole,
				Permission: body.NewPermission,
				Scope:      body.NewScope,
			},
		); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "UPDATE"})
	}
}

func revokeScopeHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body scopeRequest
		if fail := readJSON(c, &body, false); fail != nil {
			writeFailure(c, fail)
			return
		}
		if fail := service.RevokeScope(authz.LayerWrite{
			Subject:       pathParam(c, "id"),
			Role:          body.Role,
			Permission:    body.Permission,
			Scope:         body.Scope,
			OccurredAt:    body.OccurredAt,
			EffectiveFrom: body.EffectiveFrom,
		}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"event": "REVOKE"})
	}
}
