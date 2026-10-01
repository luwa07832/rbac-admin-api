package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

// NewRouter wires the public HTTP surface. Health stays at /healthz, the
// recording service lives under /api/v1, the temporal decision entry is
// GET/POST /api/v1/authorize and change history is GET/POST /api/v1/history.
// Every error keeps a single top-level error object as described in README.md.
func NewRouter(st *store.Store) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.HandleMethodNotAllowed = true

	router.GET("/healthz", func(c *gin.Context) {
		if err := st.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": gin.H{"code": "storage_unavailable", "message": "database is not available"}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "database": "ok"})
	})

	v1 := router.Group("/api/v1")
	registerAdminRoutes(v1, st)
	v1.GET("/authorize", handleAuthorize(st))
	v1.POST("/authorize", handleAuthorize(st))
	v1.GET("/history", handleHistory(st))
	v1.POST("/history", handleHistory(st))

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "route_not_found", "message": "no route matches this path"}})
	})
	router.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": gin.H{"code": "method_not_allowed", "message": "this method is not allowed for the path"}})
	})
	return router
}
