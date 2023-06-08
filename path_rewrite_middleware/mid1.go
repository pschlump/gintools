package path_rewrite_middleware

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/metrics"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

/*
// To Use
func main() {
  // ...
  api.Use(PathRewwriteMiddleware(...setup config...))
  // ...
}
*/

type PathFromToType struct {
	From     []string
	To       string
	Client   int    // non 0 causes a client side re-direct, 302, 307 for example
	Location string //
}

type PathRewriteType struct {
	PathRewrite []PathFromToType `json:"path_rewrite"`
}

var DbOn map[string]bool = make(map[string]bool)
var gCfg *PathRewriteType
var baseServerURL string
var lookup_data map[string]PathFromToType = make(map[string]PathFromToType)

// Logging and Metrics
var md *metrics.MetricsData
var logger *zap.Logger

func PathRewriteMiddleware(cfg *PathRewriteType, base string, dbF map[string]bool, lgr *zap.Logger, xmd *metrics.MetricsData) func(c *gin.Context) {

	DbOn = dbF
	gCfg = cfg
	baseServerURL = base
	logger = lgr
	md = xmd

	for _, aRewrite := range gCfg.PathRewrite {
		for _, ft := range aRewrite.From {
			lookup_data[ft] = aRewrite
		}
	}

	if xmd != nil {
		validKeys := []metrics.MetricsTypeInfo{
			{
				Key:  "path_rewrite_location",
				Desc: "Count of Rewrites via Location Header",
			},
			{
				Key:  "path_rewrite_internal",
				Desc: "Count of Rewrites Internal to Server",
			},
		}

		xmd.AddMetricsKeys(validKeys)
	}

	return func(c *gin.Context) {
		var err error

		dbgo.DbFprintf("PathRewrite.01", os.Stderr, "%(yellow)PathRewrite Before: AT: %(LF)%(reset)\nc.Request %s\nConfig %s\n", dbgo.SVarI(c.Request), dbgo.SVarI(*gCfg))

		from := fmt.Sprintf("%s", c.Request.URL)
		dbgo.DbFprintf("PathRewrite.01", os.Stderr, "At top from= ->%s<-\n", from)
		ss := strings.Split(from, "?")
		if len(ss) > 1 {
			from = ss[0]
		}
		orig := from
		foundMatch := false
		dbgo.DbFprintf("PathRewrite.01", os.Stderr, "from= ->%s<-\n", from)

		aRewrite, foundMatch := lookup_data[from]

		if foundMatch {

			if aRewrite.Client != 0 {
				dbgo.DbFprintf("PathRewrite.03", os.Stderr, "\n%(red)Client Redirect To: %s, using %d%s\n\n", aRewrite.To, aRewrite.Client)
				var to = aRewrite.Location
				if len(ss) > 1 {
					to = to + "?" + ss[1] // parse ?id= and add that back in?
				}

				to = filelib.Qt(to, map[string]string{
					"BaseServerUrl": baseServerURL,
				})

				md.AddCounter("path_rewrite_location", 1)

				if logger != nil {
					fields := []zapcore.Field{
						zap.String("message", "Location Path Rewrite"),
						zap.String("from", orig),
						zap.String("to", to),
					}
					logger.Info("log-location-rewrite", fields...)
				}

				c.Writer.Header().Set("Location", HexEscapeNonASCII(to))
				dbgo.DbFprintf("PathRewrite.03", os.Stderr, "%(magenta)Redirect from -->>%s<<-- to = -->>%s<<-- %s\n", c.Request.URL, to)
				c.Writer.WriteHeader(aRewrite.Client)
				dbgo.DbFprintf("PathRewrite.03", os.Stderr, "URL Redirect from ->%s<- to ->%s<- with a http.Status of %d AT:%(LF)\n", c.Request.URL, to, aRewrite.Client)
				return
			}

			from = aRewrite.To

			if len(ss) > 1 {
				from = from + "?" + ss[1]
			}
			c.Request.URL, err = url.Parse(from)
			if err != nil {
				dbgo.DbFprintf("PathRewrite.02", os.Stderr, "Invalid Resulting URL ->%s< from ->%s<- AT:%(LF), error=%s, config=%s\n", from, orig, err, dbgo.SVarI(*gCfg))
				c.JSON(http.StatusNotAcceptable /* 406*/, gin.H{
					"status": "error",
					"msg":    fmt.Sprintf("Invalid URL:%s", err),
				})
				return
			}

			md.AddCounter("path_rewrite_internal", 1)

			if logger != nil {
				fields := []zapcore.Field{
					zap.String("message", "Internal Path Rewrite"),
					zap.String("from", orig),
					zap.String("to", from),
				}
				logger.Info("log-internal-rewrite", fields...)
			}

			c.Request.RequestURI = from

			dbgo.DbFprintf("PathRewrite.01", os.Stderr, "%(cyan)PathRewrite After : AT:%(LF)%(reset) data=%s from=->%s<-\n", dbgo.SVarI(c.Request), from)
		}

		c.Next()
	}
}
