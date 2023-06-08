package request_id

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"github.com/gin-gonic/gin"
	"github.com/pschlump/uuid"
)

// Request ID middleware
//
// Ofter API services inject a special header X-Request-Id to response
// headers that could be used to track incoming requests for
// monitoring/debugging purposes. Value of request id header is usually
// formatted as UUID V4.
//
// After you make a request to your service, you'll see a new header in the response, similar to this one:
//
// X-Request-Id: ea9ef5f9-107b-4a4e-9295-57d701d85a92

func RequestIdMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		uuidRequestId := GenUUID()
		c.Writer.Header().Set("X-Request-Id", uuidRequestId)
		c.Set("__request_id__", uuidRequestId) // will show up in log
		c.Next()
	}
}

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}

/* vim: set noai ts=4 sw=4: */
