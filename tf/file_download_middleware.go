package tf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
)

var logFilePtr io.WriteCloser = os.Stdout // var logFilePtr *os.File = os.Stdout
var URLDownloadPath string

func InFileDownloadList(s string) (fn string, found bool) {
	// dbgo.Printf("%(cyan)===================Coupon============================%(yellow) Search for path ->%s<- data %s %(LF)\n", s, dbgo.SVarI(couponList.FromTo))

	if strings.HasPrefix(s, URLDownloadPath) {

		ext := filepath.Ext(s)

		//			if lookup in downloadable files
		//				return fn, true

		/*
			update a_applied
				set file_id = p_file_id
					, txt_file_name = p_txt_file_name
					, pdf_file_name = p_pdf_file_name
					, docx_file_name = p_docx_file_name
				where applied_id = p_applied_id
			stmt := "select 'found' from a_applied where
		*/

		fn = fmt.Sprintf("Cover-Letter%s", ext)
		found = true
	}
	return
}

// func FileDownloadMiddleware(path string, fp *os.File) gin.HandlerFunc {
func FileDownloadMiddleware(path string, fp io.WriteCloser) gin.HandlerFunc {
	URLDownloadPath = path
	logFilePtr = fp
	return func(c *gin.Context) {
		if fn, found := InFileDownloadList(c.Request.URL.Path); found {
			dbgo.Fprintf(logFilePtr, "FileDownlodMiddleware: from ->%s<- fn ->%s<- at:%(LF)\n", c.Request.URL.Path, fn)
			// Content-Disposition: attachment; filename="cool.html"
			c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fn))
		}
		c.Next()
	}
}

// func ResetLogFile(newLf *os.File) {
func ResetLogFile(newLf io.WriteCloser) {
	logFilePtr = newLf
}

/* vim: set noai ts=4 sw=4: */
