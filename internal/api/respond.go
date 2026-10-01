package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/store"
)

func respondError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{
		"code":    code,
		"message": message,
	}})
}

func respondStorageError(c *gin.Context) {
	respondError(c, http.StatusServiceUnavailable, "storage_unavailable",
		"database is not available")
}

func mapWriteError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, store.ErrNotFound):
		respondError(c, http.StatusNotFound, "record_not_found",
			"the referenced record does not exist")
		return true
	case errors.Is(err, store.ErrConflict):
		respondError(c, http.StatusConflict, "record_conflict",
			"the write conflicts with stored records")
		return true
	default:
		respondStorageError(c)
		return true
	}
}
