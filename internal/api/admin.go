package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
	"github.com/luwa07832/rbac-admin-api/internal/store"
)

type entityUpsert struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type entityRename struct {
	Name string `json:"name"`
}

type refRequest struct {
	ID string `json:"id"`
}

type scopedRoleRequest struct {
	Role  string     `json:"role"`
	Scope scopeInput `json:"scope"`
}

type scopedPermissionRequest struct {
	Permission string     `json:"permission"`
	Scope      scopeInput `json:"scope"`
}

type scopeInput struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func registerAdminRoutes(group *gin.RouterGroup, st *store.Store) {
	for _, kind := range []string{
		store.KindSubject,
		store.KindResource,
		store.KindOperation,
		store.KindPermission,
		store.KindRole,
	} {
		kind := kind
		plural := kind + "s"
		group.GET("/"+plural, listEntities(st, kind))
		group.POST("/"+plural, createEntity(st, kind))
		group.GET("/"+plural+"/:id", getEntity(st, kind))
		group.PUT("/"+plural+"/:id", updateEntity(st, kind))
		group.DELETE("/"+plural+"/:id", deleteEntity(st, kind))
	}

	group.POST("/permissions/:id/operations", addPermissionOperation(st))
	group.DELETE("/permissions/:id/operations/:operationId", removePermissionOperation(st))

	group.POST("/roles/:id/permissions", addRolePermission(st))
	group.DELETE("/roles/:id/permissions/:permissionId", removeRolePermission(st))
	group.POST("/roles/:id/parents", addRoleParent(st))
	group.DELETE("/roles/:id/parents/:parentId", removeRoleParent(st))

	group.POST("/subjects/:id/roles", bindRole(st))
	group.PUT("/subjects/:id/roles/:roleId", updateRoleScope(st))
	group.DELETE("/subjects/:id/roles/:roleId", unbindRole(st))
	group.POST("/subjects/:id/grants", grantDirect(st))
	group.DELETE("/subjects/:id/grants/:permissionId", revokeDirect(st))
}

func readJSON(c *gin.Context, target any) bool {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		respondError(c, http.StatusBadRequest, "invalid_request", "request body is not valid")
		return false
	}
	if err := decodeStrictJSON(body, target); err != nil {
		respondError(c, http.StatusBadRequest, "invalid_request", "request body is not valid")
		return false
	}
	return true
}

func listEntities(st *store.Store, kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		entities, err := st.ListEntities(kind)
		if err != nil {
			respondStorageError(c)
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": entities})
	}
}

func createEntity(st *store.Store, kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input entityUpsert
		if !readJSON(c, &input) {
			return
		}
		if !validIdentifier(input.ID) || !validName(input.Name) {
			respondError(c, http.StatusBadRequest, "invalid_request", "id and name must be valid")
			return
		}
		if err := st.PutEntity(kind, input.ID, input.Name); err != nil {
			mapWriteError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"id": input.ID, "name": input.Name})
	}
}

func getEntity(st *store.Store, kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		entity, err := st.GetEntity(kind, c.Param("id"))
		if errors.Is(err, store.ErrNotFound) {
			respondError(c, http.StatusNotFound, "record_not_found", "the record does not exist")
			return
		}
		if err != nil {
			respondStorageError(c)
			return
		}
		c.JSON(http.StatusOK, entity)
	}
}

func updateEntity(st *store.Store, kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var input entityRename
		if !readJSON(c, &input) {
			return
		}
		if !validName(input.Name) {
			respondError(c, http.StatusBadRequest, "invalid_request", "name must be valid")
			return
		}
		if exists, err := st.Exists(kind, id); err != nil {
			respondStorageError(c)
			return
		} else if !exists {
			respondError(c, http.StatusNotFound, "record_not_found", "the record does not exist")
			return
		}
		if err := st.PutEntity(kind, id, input.Name); err != nil {
			mapWriteError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": id, "name": input.Name})
	}
}

func deleteEntity(st *store.Store, kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := st.DeleteEntity(kind, c.Param("id")); err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func requireEntity(c *gin.Context, st *store.Store, kind, id string) bool {
	exists, err := st.Exists(kind, id)
	if err != nil {
		respondStorageError(c)
		return false
	}
	if !exists {
		respondError(c, http.StatusNotFound, "record_not_found", "the referenced record does not exist")
		return false
	}
	return true
}

func addPermissionOperation(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissionID := c.Param("id")
		var input refRequest
		if !readJSON(c, &input) || !validIdentifier(input.ID) {
			respondError(c, http.StatusBadRequest, "invalid_request", "operation id must be valid")
			return
		}
		if !requireEntity(c, st, store.KindPermission, permissionID) ||
			!requireEntity(c, st, store.KindOperation, input.ID) {
			return
		}
		if err := st.AddLink("permission_operations", permissionID, input.ID); err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func removePermissionOperation(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := st.RemoveLink("permission_operations", c.Param("id"), c.Param("operationId")); err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func addRolePermission(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("id")
		var input refRequest
		if !readJSON(c, &input) || !validIdentifier(input.ID) {
			respondError(c, http.StatusBadRequest, "invalid_request", "permission id must be valid")
			return
		}
		if !requireEntity(c, st, store.KindRole, roleID) ||
			!requireEntity(c, st, store.KindPermission, input.ID) {
			return
		}
		if err := st.AuthorizeRolePermission(roleID, input.ID); err != nil {
			if errors.Is(err, store.ErrAlreadyOpen) {
				c.Status(http.StatusNoContent)
				return
			}
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func removeRolePermission(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := st.RevokeRolePermission(c.Param("id"), c.Param("permissionId")); err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func addRoleParent(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID := c.Param("id")
		var input refRequest
		if !readJSON(c, &input) || !validIdentifier(input.ID) {
			respondError(c, http.StatusBadRequest, "invalid_request", "parent role id must be valid")
			return
		}
		if !requireEntity(c, st, store.KindRole, roleID) ||
			!requireEntity(c, st, store.KindRole, input.ID) {
			return
		}
		if err := st.AddRoleInheritance(roleID, input.ID); err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func removeRoleParent(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := st.RemoveRoleInheritance(c.Param("id"), c.Param("parentId")); err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func parseDeleteScope(c *gin.Context) (authz.Scope, bool) {
	kind := c.Query("scope_kind")
	value := c.Query("scope_value")
	if !authz.ValidScope(kind, value) {
		respondError(c, http.StatusBadRequest, "invalid_request",
			"scope_kind and scope_value must describe a valid scope")
		return authz.Scope{}, false
	}
	return authz.Scope{Kind: kind, Value: value}, true
}

func bindRole(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		subjectID := c.Param("id")
		var input scopedRoleRequest
		if !readJSON(c, &input) || !validIdentifier(input.Role) ||
			!authz.ValidScope(input.Scope.Kind, input.Scope.Value) {
			respondError(c, http.StatusBadRequest, "invalid_request",
				"role id and scope must be valid")
			return
		}
		if !requireEntity(c, st, store.KindSubject, subjectID) ||
			!requireEntity(c, st, store.KindRole, input.Role) {
			return
		}
		if err := st.BindSubjectRole(subjectID, input.Role, input.Scope.Kind, input.Scope.Value); err != nil {
			if errors.Is(err, store.ErrAlreadyOpen) {
				c.Status(http.StatusNoContent)
				return
			}
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// updateRoleScope replaces the scope of one open binding: the old window closes
// at the change instant and a new window opens, which history reports as UPDATE.
func updateRoleScope(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		subjectID := c.Param("id")
		roleID := c.Param("roleId")
		oldScope, ok := parseDeleteScope(c)
		if !ok {
			return
		}
		var input struct {
			Scope scopeInput `json:"scope"`
		}
		if !readJSON(c, &input) ||
			!authz.ValidScope(input.Scope.Kind, input.Scope.Value) {
			respondError(c, http.StatusBadRequest, "invalid_request",
				"the new scope must be valid")
			return
		}
		if !requireEntity(c, st, store.KindSubject, subjectID) ||
			!requireEntity(c, st, store.KindRole, roleID) {
			return
		}
		err := st.UpdateSubjectRoleScope(subjectID, roleID,
			oldScope.Kind, oldScope.Value, input.Scope.Kind, input.Scope.Value)
		if err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func unbindRole(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		scope, ok := parseDeleteScope(c)
		if !ok {
			return
		}
		if err := st.UnbindSubjectRole(c.Param("id"), c.Param("roleId"), scope.Kind, scope.Value); err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func grantDirect(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		subjectID := c.Param("id")
		var input scopedPermissionRequest
		if !readJSON(c, &input) || !validIdentifier(input.Permission) ||
			!authz.ValidScope(input.Scope.Kind, input.Scope.Value) {
			respondError(c, http.StatusBadRequest, "invalid_request",
				"permission id and scope must be valid")
			return
		}
		if !requireEntity(c, st, store.KindSubject, subjectID) ||
			!requireEntity(c, st, store.KindPermission, input.Permission) {
			return
		}
		if err := st.GrantDirect(subjectID, input.Permission, input.Scope.Kind, input.Scope.Value); err != nil {
			if errors.Is(err, store.ErrAlreadyOpen) {
				c.Status(http.StatusNoContent)
				return
			}
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func revokeDirect(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		scope, ok := parseDeleteScope(c)
		if !ok {
			return
		}
		if err := st.RevokeDirect(c.Param("id"), c.Param("permissionId"), scope.Kind, scope.Value); err != nil {
			mapWriteError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}
