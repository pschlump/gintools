package path_rewriter

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// Match paths that need to be re-mapped to a destination path.  For example in a single page
// application a path of /create may need to be mapped back to / so that index.html is rendered.
//
// Code from Go-FTL server, Copyright 2014-2018, Philip Schlump.
// .../github.com/pschlump/Go-FTL/server/midlib/Rewrite/rewrite.go
// and is BSD 3 Clause Licensed.

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"go.uber.org/zap"
)

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
var sugar *zap.SugaredLogger
var gCfg *PathRewriteType
var baseServerURL string

func init() {
	gCfg = &PathRewriteType{
		PathRewrite: []PathFromToType{},
	}
}

func NewPathRewriteHandler(handler http.Handler, cfg *PathRewriteType, b string, dbF map[string]bool, sug *zap.SugaredLogger) http.Handler {
	DbOn = dbF
	sugar = sug
	gCfg = cfg
	baseServerURL = b
	return http.HandlerFunc(func(www http.ResponseWriter, req *http.Request) {

		if DbOn["PathRewrite.01"] {
			fmt.Printf("%sPathRewrite Before: AT: %s%s\nreq %s\nConfig %s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.ColorReset, dbgo.SVarI(req), dbgo.SVarI(*gCfg))
		}

		from := fmt.Sprintf("%s", req.URL)
		if DbOn["PathRewrite.01"] {
			fmt.Printf("At top from= ->%s<-\n", from)
		}
		ss := strings.Split(from, "?")
		if len(ss) > 1 {
			from = ss[0]
		}
		orig := from
		foundMatch := false
		if DbOn["PathRewrite.01"] {
			fmt.Printf("from= ->%s<-\n", from)
		}
		for jj, aRewrite := range gCfg.PathRewrite {
			for ii, ft := range aRewrite.From {
				if from == ft {
					foundMatch = true
					if aRewrite.Client != 0 {
						fmt.Fprintf(os.Stderr, "\n%s Client Redirect To: %s, using %d%s\n\n", dbgo.ColorRed, aRewrite.To, aRewrite.Client, dbgo.ColorReset)
						var to = aRewrite.Location
						if len(ss) > 1 {
							to = to + "?" + ss[1] // parse ?id= and add that back in?
						}

						to = filelib.Qt(to, map[string]string{
							"BaseServerUrl": baseServerURL,
						})

						www.Header().Set("Location", HexEscapeNonASCII(to))
						fmt.Fprintf(os.Stderr, "%s Redirect from -->>%s<<-- to = -->>%s<<-- %s\n", dbgo.ColorMagenta, req.URL, to, dbgo.ColorReset)
						www.WriteHeader(aRewrite.Client)
						fmt.Fprintf(os.Stderr, "URL Redirect from ->%s<- to ->%s<- with a http.Status of %d at:%s\n", req.URL, to, aRewrite.Client, dbgo.LF())
						return
					} else {
						from = aRewrite.To
						if DbOn["PathRewrite.01"] {
							fmt.Printf("%sFound a Match at %d / %d  ->%s<-%s\n", dbgo.ColorRed, jj, ii, ft, dbgo.ColorReset)
						}
						break
					}
				}
			}
		}
		if foundMatch {
			var err error
			if len(ss) > 1 {
				from = from + "?" + ss[1]
			}
			req.URL, err = url.Parse(from)
			if err != nil {
				www.WriteHeader(http.StatusNotAcceptable) // 406
				fmt.Fprintf(www, `{"status":"error","msg":"Invalid url:%s"}`, err)
				if DbOn["PathRewrite.02"] {
					fmt.Fprintf(os.Stderr, "Invalid Resulting URL ->%s< from ->%s<- at:%s, error=%s, config=%s\n", from, orig, dbgo.LF(), err, dbgo.SVarI(*gCfg))
				}
				// xyzzy - Log error
				return
			}

			LogIntrnalRewrite(orig, from)

			req.RequestURI = from

			if DbOn["PathRewrite.01"] {
				fmt.Printf("%sPathRewrite After : AT: %s%s data=%s from=->%s<-\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset, dbgo.SVarI(req), from)
			}
		}

		// h.handler.ServeHTTP(www, req)
		handler.ServeHTTP(www, req)
	})
}

func LogIntrnalRewrite(from string, to string) {
	sugar.Infow("PathRewrite",
		"from", from,
		"to", to,
	)
}

/* vim: set noai ts=4 sw=4: */
