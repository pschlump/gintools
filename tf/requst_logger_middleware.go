package tf

// Copyright (C) Philip Schlump 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/uuid"
)

type RequestLogFile struct {
	// logFilePtr *os.File
	logFilePtr io.WriteCloser
	createdAt  time.Time
	refCount   int
}

var logFilePointerTable = make(map[string]*RequestLogFile)
var logFilePointerLock sync.RWMutex

// func GetLogFile(requestId string) (fpOut *os.File) {
func GetLogFile(requestId string) (fpOut io.WriteCloser) {
	logFilePointerLock.Lock()
	defer logFilePointerLock.Unlock()
	lf, ok := logFilePointerTable[requestId]
	if ok {
		fpOut = lf.logFilePtr
		return
	}
	fpOut = logFilePtr
	return
}

// func SetLogFile(requestId string, fp *os.File) {
func SetLogFile(requestId string, fp io.WriteCloser) {
	logFilePointerLock.Lock()
	defer logFilePointerLock.Unlock()
	logFilePointerTable[requestId] = &RequestLogFile{
		logFilePtr: fp,
		createdAt:  time.Now(),
		refCount:   1,
	}
}

func AddRefCount(requestId string) {
	logFilePointerLock.Lock()
	defer logFilePointerLock.Unlock()
	lf, ok := logFilePointerTable[requestId]
	if ok {
		lf.refCount++
		logFilePointerTable[requestId] = lf
	}
}

func CloseLogFile(requestId string) {
	logFilePointerLock.Lock()
	defer logFilePointerLock.Unlock()
	lf, ok := logFilePointerTable[requestId]
	if ok {
		lf.refCount--
		logFilePointerTable[requestId] = lf
		if lf.refCount <= 0 {
			lf.logFilePtr.Close()
			delete(logFilePointerTable, requestId)
			return
		}
	}
}

func TimedCleanupLogFile() {
	// iterate over, if timeout #1 then close and set to os.Stderr, delete item
	dbgo.Fprintf(logFilePtr, "In tf.TimedCleanupLogFile(), %(LF)\n")
	current_time := time.Now()
	logFilePointerLock.Lock()
	defer logFilePointerLock.Unlock()
	for requestId, val := range logFilePointerTable {
		cc := val.createdAt
		exp := cc.Add(10 * time.Minute)
		if exp.Before(current_time) {
			dbgo.Fprintf(logFilePtr, "In tf.TimedCleanupLogFile(), %(LF), found %s to cleanup\n", requestId)
			val.logFilePtr.Close()
			delete(logFilePointerTable, requestId)
		}
	}
}

// func GetLogFilePtr(c *gin.Context) (perReqLog *os.File) {
func GetLogFilePtr(c *gin.Context) (perReqLog io.WriteCloser) {
	if c == nil {
		return logFilePtr
	}
	requestId, _ := c.Get("__request_id__")
	perReqLog = GetLogFile(requestId.(string))
	return
}

func RequestLogger(LogFileName string) gin.HandlerFunc {
	return func(c *gin.Context) {

		uuidRequestId := GenUUID()

		// logFn := fmt.Sprintf("%s.RequestId_%s.log", LogFileName, uuidRequestId)
		// dbgo.Fprintf(os.Stderr, "%(cyan)Logging to: request_id=%s, file=%s\n", uuidRequestId, logFn)
		fmt.Fprintf(logFilePtr, "Logging to: request_id=%s\n", uuidRequestId)

		// f, err := filelib.Fopen(logFn, "w")

		_, f, err := NewRedisLogger(uuidRequestId, rdb, ctx)
		if err != nil {
			// fmt.Fprintf(os.Stderr, "Unable to open file for [%s] error: %s\n", logFn, err)
			fmt.Fprintf(os.Stderr, "Unable to open connection to logger RequestId=[%s] error: %s\n", uuidRequestId, err)
			f = os.Stderr
		}

		SetLogFile(uuidRequestId, f)

		// dbgo.Fprintf(os.Stderr, "%(yellow)AT:%(LF) before request - request_id = %s\n", uuidRequestId)
		c.Writer.Header().Set("X-Request-Id", uuidRequestId)
		c.Set("__request_id__", uuidRequestId) // will show up in log

		// dbgo.Fprintf(f, "%(magenta)At:%(LF)\n")
		dbgo.Fprintf(f, "%(magenta)===  Request  ===============================================================================================================%(reset)\n%(yellow)URI=%(red)%s: %s, request_id=%s%(yellow)\nHeaders\n", c.Request.Method, c.Request.URL.RequestURI(), uuidRequestId)
		for name, values := range c.Request.Header {
			// Loop over all values for the name.
			for _, value := range values {
				dbgo.Fprintf(f, "%(yellow)\t%s ->%s<-\n", name, value)
			}
		}

		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				dbgo.Fprintf(f, "%(red)request body peek resulted in error: %s\n", err)
			} else {
				dbgo.Fprintf(f, "%(yellow)request body ->%s<-\n", body)
				c.Request.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		c.Next()

		dbgo.Fprintf(os.Stderr, "%(yellow)AT:%(LF) after request - request_id = %s\n", uuidRequestId)
		CloseLogFile(uuidRequestId)
	}
}

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
		dbgo.Fprintf(os.Stderr, "%(yellow)AT:%(LF) before request - request_id = %s\n", uuidRequestId)
		c.Writer.Header().Set("X-Request-Id", uuidRequestId)
		c.Set("__request_id__", uuidRequestId) // will show up in log
		c.Next()
		dbgo.Fprintf(os.Stderr, "%(yellow)AT:%(LF) after request - request_id = %s\n", uuidRequestId)
	}
}

// GenUUID generates a UUID and returns it.
func GenUUID() string {
	newUUID, _ := uuid.NewV4() // Intentionally ignore errors - function will never return any.
	return newUUID.String()
}

/* vim: set noai ts=4 sw=4: */
