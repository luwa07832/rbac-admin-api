package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// NewRouter wires the public HTTP surface. The service contract in README.md
// describes the error shape every entry must keep.
func NewRouter(st *store.Store) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	// Identifiers may contain "/" (e.g. "tenant-a/doc-1"); keep %2F encoded
	// inside a single path parameter instead of splitting the route.
	router.UseRawPath = true
	router.UnescapePathValues = false
	router.Use(gin.Recovery())

	service := authz.NewService(st)

	router.GET("/healthz", func(c *gin.Context) {
		if err := st.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": gin.H{"code": "storage_unavailable", "message": "database is not available"}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "database": "ok"})
	})

	registerCatalog(router, service, "subjects", store.CatalogSubject)
	registerCatalog(router, service, "resources", store.CatalogResource)
	registerCatalog(router, service, "operations", store.CatalogOperation)
	registerCatalog(router, service, "roles", store.CatalogRole)
	registerCatalog(router, service, "permissions", store.CatalogPermission)

	router.PUT("/roles/:id/parents", setRoleParentsHandler(service))
	router.PUT("/permissions/:id/operations", setPermissionOperationsHandler(service))

	router.PUT("/subjects/:id/bindings/:role", grantBindingHandler(service))
	router.PATCH("/subjects/:id/bindings/:role", updateBindingHandler(service))
	router.DELETE("/subjects/:id/bindings/:role", revokeBindingHandler(service))

	router.PUT("/roles/:id/permissions/:perm", grantRolePermissionHandler(service))
	router.PATCH("/roles/:id/permissions/:perm", updateRolePermissionHandler(service))
	router.DELETE("/roles/:id/permissions/:perm", revokeRolePermissionHandler(service))

	router.PUT("/subjects/:id/scopes", grantScopeHandler(service))
	router.PATCH("/subjects/:id/scopes", updateScopeHandler(service))
	router.DELETE("/subjects/:id/scopes", revokeScopeHandler(service))

	router.POST("/authorize", authorizeHandler(service))
	router.GET("/history", historyHandler(service))
	router.GET("/subjects/:id/access", subjectAccessHandler(service))

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "route_not_found", "message": "no route matches this path"}})
	})
	return router
}

func registerCatalog(router *gin.Engine, service *authz.Service, segment string, kind store.CatalogKind) {
	router.PUT("/"+segment+"/:id", func(c *gin.Context) {
		if fail := service.Register(authz.RegisterInput{Kind: kind, ID: pathParam(c, "id")}); fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"registered": true})
	})
}
