package version

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"runtime"

	"github.com/gin-gonic/gin"
)

var version string
var appName string
var gitCommit string
var xHeader string
var buildDate string

// SetVersion for setup version string.
func SetVersion(ver, name, git, bdate string) {
	version, appName, gitCommit, buildDate = ver, name, git, bdate
	xHeader = fmt.Sprintf("X-%s-Version", version)
}

// GetVersion for get current version.
func GetVersion() string {
	return version
}
func GetAppName() string {
	return appName
}
func GetGitCommit() string {
	return gitCommit
}

// PrintVersion print out the current version of application and compiler.
func PrintVersion() {
	fmt.Printf("%s: Version:%s (Git Commit:%s, Build Date:%s), Compiler Version: %s %s\n", appName, version, gitCommit, buildDate, runtime.Compiler, runtime.Version())
}

// VersionMiddleware : add version to header.
func VersionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header(xHeader, version)
		c.Next()
	}
}
