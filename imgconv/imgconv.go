package imgconv

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	_ "image/png"
	"io/ioutil"
	"os"
	"os/exec"
	"path"

	//	"github.com/jdeng/goheif"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/image/webp"
)

var splitPdf = "./cd-pdftoppm.sh"
var tmpPathPdf = "./www/files"
var logFilePtr = os.Stderr
var logger *zap.Logger

func ConvPdfToPngSetup(ex, dir string, log *os.File, lgr *zap.Logger) {
	splitPdf = ex
	tmpPathPdf = dir
	logFilePtr = log
	logger = lgr
}

func ConvJpegToPng(inputFn string) (fn string, err error) {
	fp, err := filelib.Fopen(inputFn, "r")
	if err != nil {
		return
	}
	defer fp.Close()
	img, _, err := image.Decode(fp)
	fn = fileToPng(inputFn)
	out, err := filelib.Fopen(fn, "w")
	if err != nil {
		return
	}
	err = png.Encode(out, img)
	if err != nil {
		return
	}
	return
}

func ConvGifToPng(inputFn string) (fn string, err error) {
	fp, err := filelib.Fopen(inputFn, "r")
	if err != nil {
		return
	}
	defer fp.Close()
	img, _, err := image.Decode(fp)
	fn = fileToPng(inputFn)
	out, err := filelib.Fopen(fn, "w")
	if err != nil {
		return
	}
	err = png.Encode(out, img)
	if err != nil {
		return
	}
	return
}

//func ConvHeicToPng(inputFn string) (fn string, err error) {
//	fp, err := filelib.Fopen(inputFn, "r")
//	if err != nil {
//		return
//	}
//	defer fp.Close()
//	img, err := goheif.Decode(fp)
//	fn = fileToPng(inputFn)
//	out, err := filelib.Fopen(fn, "w")
//	if err != nil {
//		return
//	}
//	err = png.Encode(out, img)
//	if err != nil {
//		return
//	}
//	return
//}

func ConvWebpToPng(inputFn string) (fn string, err error) {
	fp, err := filelib.Fopen(inputFn, "r")
	if err != nil {
		return
	}
	defer fp.Close()
	img, err := webp.Decode(fp) // func Decode(r io.Reader) (image.Image, error) {
	fn = fileToPng(inputFn)
	out, err := filelib.Fopen(fn, "w")
	if err != nil {
		return
	}
	err = png.Encode(out, img)
	if err != nil {
		return
	}
	return
}

/*

		dbgo.Printf("at:%(LF)\n")
		cmd := exec.Command(gCfg.PdfCpu, vn...)
		buf, err := cmd.CombinedOutput()
		if err != nil {
			dbgo.Fprintf(os.Stderr, "%(red)%s: PDF Generation Error: error:%s, input %s\n", dbgo.LF(), err, YData(vn...))
			fmt.Fprintf(logFilePtr, "%s: PDF Generation Error: error:%s, input %s\n", dbgo.LF(), err, YData(vn...))
			c.JSON(http.StatusBadRequest, gin.H{
				"status":   "error",
				"msg":      "Unable to create .pdf file for factoring (4).",
				"location": dbgo.LF(),
			})
			return
		}
		fmt.Printf("Result ->%s<-\n", buf)

---



Convert PDF Document to Image
The syntax for converting an entire pdf is as follows:

$ pdftoppm -<image_format> <pdf_filename> <image_name>
$ pdftoppm -<image_format> <pdf_filename> <image_name>
In the example below, the name of my document is Linux_For_Beginners.pdf and we will convert it to PNG format and name the images as Linux_For_Beginners.

$ pdftoppm -png Linux_For_Beginners.pdf Linux_For_Beginners
Each page of the PDF will be converted to



GPL v.2
##		# convert pdf to a set of .png images:  https://github.com/freedesktop/poppler
##		# Go bindings for: https://github.com/cheggaaa/go-poppler
##		#
##		$ pdftoppm -png d1a1fbbe-0037-402f-4e69-4d3d058eeaad.pdf test001

*/

func ConvPdfToPng(inputFn string) (fns []string, dir string, err error) {

	if db1 {
		dbgo.Printf("at:%(LF)\n")
	}
	baseName := path.Base(inputFn)
	baseNoExt := filelib.RmExt(baseName)

	os.MkdirAll(tmpPathPdf, 0755)

	// create working dir for this, set dir string
	dir, err = ioutil.TempDir(tmpPathPdf, baseNoExt)
	if err != nil {
		if db1 {
			dbgo.Printf("at:%(LF)\n")
		}
		return
	}
	if db1 {
		dbgo.Printf("at:%(LF) dir = ->%s<-\n", dir)
	}

	// link input file into working dir
	pdfFileName := path.Join(dir, baseName)
	if err = os.Link(inputFn, pdfFileName); err != nil {
		if db1 {
			dbgo.Printf("at:%(LF)\n")
		}
		return
	}

	// call program to split PNG into files
	if db1 {
		dbgo.Printf("at:%(LF)\n")
	}
	// cmd := exec.Command(splitPdf, dir, "-png", pdfFileName, baseName)
	cmd := exec.Command(splitPdf, dir, "-png", baseName, baseName)
	buf, err := cmd.CombinedOutput()
	if err != nil {
		if logger != nil {
			fields := []zapcore.Field{
				zap.String("message", fmt.Sprintf("%s: PDF Split Error", dbgo.LF())),
				zap.Error(err),
				zap.String("splitPdf", splitPdf),
				zap.String("dir", dir),
				zap.String("pdfFileName", pdfFileName),
				zap.String("baseName", baseName),
			}
			logger.Error("failed-to-split-PDF-file", fields...)
		} else {
			dbgo.Fprintf(os.Stderr, "%(red)%(LF): PDF Split Error: error:%s, run %s %s %s %s\n", err, splitPdf, dir, "-png", pdfFileName, baseName)
			dbgo.Fprintf(logFilePtr, "%(LF): PDF Split Error: error:%s, run %s %s %s %s\n", err, splitPdf, dir, "-png", pdfFileName, baseName)
		}
		err = fmt.Errorf("Unable to split .pdf file for factoring (Error:%s).", err)
		return
	}

	// read in list of files in direcotyr
	fns, _ = filelib.GetFilenames(dir)
	fns = filelib.RemoveMatch("^"+baseName+"$", fns)

	if db1 {
		dbgo.Printf("%(yellow)at:%(LF) Result ->%s<-, output list = %s\n", buf, fns)
	}
	return
}

//func RemoveMatch(re string, inArr []string) (outArr []string) {
//	var validID = regexp.MustCompile(re)
//
//	outArr = make([]string, 0, len(inArr))
//	for k := range inArr {
//		if !validID.MatchString(inArr[k]) {
//			outArr = append(outArr, inArr[k])
//		}
//	}
//	// fmt.Printf ( "output = %v\n", outArr )
//	return
//}

func fileToPng(inputFn string) (fn string) {
	inputFn = filelib.RmExt(inputFn)
	fn = inputFn + ".png"
	return
}

const db1 = false

/* vim: set noai ts=4 sw=4: */
