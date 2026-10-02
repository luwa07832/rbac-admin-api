package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/luwa07832/rbac-admin-api/internal/authz"
)

// subjectAccessHandler answers the read-only effective authorization listing
// for one subject. effectiveAt is optional and defaults to the current time.
func subjectAccessHandler(service *authz.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		entries, fail := service.Access(authz.AccessInput{
			Subject:     pathParam(c, "id"),
			EffectiveAt: c.Query("effectiveAt"),
		})
		if fail != nil {
			writeFailure(c, fail)
			return
		}
		c.JSON(http.StatusOK, gin.H{"access": entries})
	}
}
