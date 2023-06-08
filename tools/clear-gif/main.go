package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/pschlump/filelib"
)

const base64GifPixel = "R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs="

/*
//  	/api/clr.gif?_cache_burst_=444randomnumber

func loginTrackingGifhandler(c *gin.Context) {

	// Note: See Line: https://golang.org/src/net/http/fs.go 337
	// w.Header().get("Etag")
	im := c.Request.Header.Get("If-Match")
	inm := c.Request.Header.Get("If-None-Match")
	etag := c.Request.Header.Get("Etag")
	if im != "" || inm != "" || etag != "" {
		// RFC 7232 section 4.1:
		// a sender SHOULD NOT generate representation metadata other than the
		// above listed fields unless said metadata exists for the purpose of
		// guiding cache updates (e.g., Last-Modified might be useful if the
		// response does not have an ETag field).
		if etag == "" {
			etag = GenUUID()
			fmt.Fprintf(logFilePtr, "ETag: %s new\n", etag)
		} else {
			fmt.Fprintf(logFilePtr, "ETag: %s previous\n", etag)
		}
		h := c.Writer.Header()
		delete(h, "Content-Type")
		delete(h, "Content-Length")
		delete(h, "Last-Modified")
		delete(h, "ETag")
		h.Set("ETag", etag)
		c.Writer.WriteHeader(http.StatusNotModified)
		return
	}

	etag = GenUUID()
	c.Writer.Header().Set("Content-Type", "image/gif")
	c.Writer.Header().Set("ETag", etag)
	fmt.Fprintf(logFilePtr, "ETag: %s new\n", etag)
	output, _ := base64.StdEncoding.DecodeString(base64GifPixel)
	io.WriteString(c.Writer, string(output))
}
*/

func main() {

	fo, err := filelib.Fopen("test.gif", "w")
	if err != nil {
		fmt.Printf("unable to open output: %s\n", err)
		os.Exit(1)
	}

	output, err := base64.StdEncoding.DecodeString(base64GifPixel)
	if err != nil {
		fmt.Printf("erro on base64 encode: %s\n", err)
		os.Exit(1)
	}

	io.WriteString(fo, string(output))

}
