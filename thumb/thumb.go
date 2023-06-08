package thumb

// Copyright (C) Philip Schlump, 2016-2018, 2022.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"image"
	"image/color"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/disintegration/imaging"
	"github.com/gin-gonic/gin"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/jwt_auth"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var DbOn map[string]bool
var logFilePtr *os.File
var gCfg *data.ThumbnailType
var xCfg *data.BaseConfigType
var logger *zap.Logger

func SetupThumbnail(router *gin.Engine, cfg *data.ThumbnailType, xcfg *data.BaseConfigType, dbF map[string]bool, f *os.File, lfp *zap.Logger) {
	DbOn = dbF
	logFilePtr = f
	gCfg = cfg
	xCfg = xcfg
	logger = lfp

	if !filelib.Exists(gCfg.ThumbnailPath) {
		fmt.Printf("Missing directory [%s] creating it\n", gCfg.ThumbnailPath)
		os.MkdirAll(gCfg.ThumbnailPath, 0755)
	}
	router.GET("/api/v1/thumbnail", ThumbnailImage)
	router.GET("/api/v1/thumbnail-url", ThumbnailURL)
}

type ApiThumbInput struct {
	FnUrl string `json:"fn" form:"fn"`
	W     *int   `json:"w" form:"w"`
	H     *int   `json:"h" form:"h"`
}

// Returns a Thumbnail for an image
func ThumbnailImage(c *gin.Context) {

	if DbOn["thumb.01"] {
		fmt.Printf("%sAT: %s Thumbnail Top %s\n", dbgo.ColorBlueOnWhite, dbgo.LF(), dbgo.ColorReset)
	}

	if !filelib.Exists(gCfg.ThumbnailPath) {
		os.MkdirAll(gCfg.ThumbnailPath, 0755)
	}

	var pp ApiThumbInput
	if err := jwt_auth.BindFormOrJSON(c, &pp); err != nil {
		return
	}

	fn := ConvertUrlToPath(pp.FnUrl)
	if fn == "" {
		gid := jwt_auth.GenUUID()
		if logger == nil {
			fields := []zapcore.Field{
				zap.String("message", "invalid file"),
				zap.String("gid", gid),
				zap.String("location", dbgo.LF()),
			}
			logger.Error("invalid-file", fields...)
		} else {
			fmt.Fprintf(logFilePtr, `{"status":"error","status_code":%d,"msg":"Invalid File","error-id":%q,"invalid-file":%q,"AT":%q}`+"\n", http.StatusNotAcceptable, gid, pp.FnUrl, dbgo.LF())
		}
		c.JSON(http.StatusNotAcceptable, gin.H{ // 406
			"status":   "error",
			"location": dbgo.LF(),
			"msg":      fmt.Sprintf("Error: Invalid File %s", fn),
		})
		return
	}

	var OW, OH int
	if pp.W != nil {
		OW = *pp.W
	} else {
		OW = 250
	}
	if pp.H != nil {
		OH = *pp.H
	} else {
		OH = 0
	}

	bn := path.Base(fn)
	dst := fmt.Sprintf("%s/%03dx%03d-%s", gCfg.ThumbnailPath, OW, OH, bn)

	if DbOn["thumb.01"] {
		fmt.Printf("%sAT: %s Thumbnail pp.FnUrl >%s< fn >%s< w=%d h=%d, bn >%s< dst >%s< %s\n", dbgo.ColorCyan, dbgo.LF(), pp.FnUrl, fn, OW, OH, bn, dst, dbgo.ColorReset)
	}

	fns := []string{fn}
	if !filelib.Exists(dst) {
		// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
		err := GenThumbnail(fns, int(OW), 0, int(OW), int(OH), dst)
		// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
		if err != nil {
			// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
			gid := jwt_auth.GenUUID()
			if logger == nil {
				fields := []zapcore.Field{
					zap.String("message", "invalid file"),
					zap.String("FnUrl", pp.FnUrl),
					zap.String("location", dbgo.LF()),
				}
				logger.Error("invalid-file", fields...)
			} else {
				fmt.Fprintf(logFilePtr, `{"status":"error","status_code":%d,"msg":"Invalid File","error-id":%q,"invalid-file":%q,"AT":%q}`+"\n", http.StatusNotAcceptable, gid, pp.FnUrl, dbgo.LF())
			}
			c.JSON(http.StatusNotAcceptable, gin.H{ // 406
				"status":   "error",
				"location": dbgo.LF(),
				"msg":      fmt.Sprintf("Error: Invalid File %s", err),
			})
			return
		}
	}

	// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
	buf, err := ioutil.ReadFile(dst)
	if err != nil {
		// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
		gid := jwt_auth.GenUUID()
		if logger == nil {
			fields := []zapcore.Field{
				zap.String("message", "invalid file"),
				zap.String("FnUrl", pp.FnUrl),
				zap.String("error_id", gid),
				zap.String("location", dbgo.LF()),
			}
			logger.Error("invalid-file", fields...)
		} else {
			fmt.Fprintf(logFilePtr, `{"status":"error","status_code":%d,"msg":"Invalid File","error-id":%q,"invalid-file":%q,"AT":%q}`+"\n", http.StatusNotAcceptable, gid, pp.FnUrl, dbgo.LF())
		}
		c.JSON(http.StatusNotAcceptable, gin.H{ // 406
			"status":   "error",
			"location": dbgo.LF(),
			"msg":      fmt.Sprintf("Error: Invalid File %s", err),
		})
		return
	}
	// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
	c.Writer.Header().Set("Content-Type", "image/jpeg")
	c.Writer.WriteHeader(http.StatusOK) // 200
	c.Writer.Write(buf)
}

func ThumbnailURL(c *gin.Context) {

	dbgo.Printf("%(red)%(LF): Thumbnail\n")
	if DbOn["thumb.01"] {
		fmt.Printf("%sAT: %s Thumbnail Top %s\n", dbgo.ColorBlueOnWhite, dbgo.LF(), dbgo.ColorReset)
	}

	if !filelib.Exists(gCfg.ThumbnailPath) {
		os.MkdirAll(gCfg.ThumbnailPath, 0755)
	}

	var pp ApiThumbInput
	if err := jwt_auth.BindFormOrJSON(c, &pp); err != nil {
		dbgo.Printf("%(red)%(LF): Thumbnail\n")
		return
	}

	dbgo.Printf("%(red)%(LF): Thumbnail\n")
	fn := ConvertUrlToPath(pp.FnUrl)
	if fn == "" {
		// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
		dbgo.Printf("%(red)%(LF): Thumbnail\n")
		gid := jwt_auth.GenUUID()
		if logger == nil {
			fields := []zapcore.Field{
				zap.String("message", "invalid file"),
				zap.String("FnUrl", pp.FnUrl),
				zap.String("error_id", gid),
				zap.String("location", dbgo.LF()),
			}
			logger.Error("invalid-file", fields...)
		} else {
			fmt.Fprintf(logFilePtr, `{"status":"error","status_code":%d,"msg":"Invalid File","error-id":%q,"invalid-file":%q,"AT":%q}`+"\n", http.StatusNotAcceptable, gid, pp.FnUrl, dbgo.LF())
		}
		c.JSON(http.StatusNotAcceptable, gin.H{ // 406
			"status":   "error",
			"location": dbgo.LF(),
			"msg":      fmt.Sprintf("Error: Invalid File %s", fn),
		})
		return
	}

	dbgo.Printf("%(red)%(LF): Thumbnail\n")
	// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
	var OW, OH int
	if pp.W != nil {
		OW = *pp.W
	} else {
		OW = 250
	}
	if pp.H != nil {
		OH = *pp.H
	} else {
		OH = 0
	}

	bn := path.Base(fn)
	dst := fmt.Sprintf("%s/%03dx%03d-%s", gCfg.ThumbnailPath, OW, OH, bn)
	dbgo.Printf("%(red)%(LF): Thumbnail\n")

	if DbOn["thumb.01"] {
		fmt.Printf("%sAT: %s Thumbnail pp.FnUrl >%s< fn >%s< w=%d h=%d, bn >%s< dst >%s< %s\n", dbgo.ColorCyan, dbgo.LF(), pp.FnUrl, fn, OW, OH, bn, dst, dbgo.ColorReset)
	}

	fns := []string{fn}
	dbgo.Printf("%(red)%(LF): Thumbnail\n")
	if !filelib.Exists(dst) {
		// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
		err := GenThumbnail(fns, int(OW), 0, int(OW), int(OH), dst)
		dbgo.Printf("%(red)%(LF): Thumbnail\n")
		// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
		if err != nil {
			// fmt.Printf("%sAT: %s Thumbnail %s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
			gid := jwt_auth.GenUUID()
			if logger == nil {
				fields := []zapcore.Field{
					zap.String("message", "invalid file"),
					zap.String("FnUrl", pp.FnUrl),
					zap.String("error_id", gid),
					zap.String("location", dbgo.LF()),
				}
				logger.Error("invalid-file", fields...)
			} else {
				fmt.Fprintf(logFilePtr, `{"status":"error","status_code":%d,"msg":"Invalid File","error-id":%q,"invalid-file":%q,"AT":%q}`+"\n", http.StatusNotAcceptable, gid, pp.FnUrl, dbgo.LF())
			}
			c.JSON(http.StatusNotAcceptable, gin.H{ // 406
				"status":   "error",
				"location": dbgo.LF(),
				"msg":      fmt.Sprintf("Error: Invalid File %s", err),
			})
			return
		}
	}

	dbgo.Printf("%(red)%(LF): Thumbnail\n")
	dstURL := fmt.Sprintf("%s/%03dx%03d-%s", gCfg.ThumbnailPathURL, OW, OH, bn)

	dbgo.Printf("%(red)%(LF): Thumbnail\n")
	c.JSON(http.StatusOK, gin.H{ // 200
		"status": "success",
		"url":    dstURL,
	})

}

func ConvertUrlToPath(fnUrl string) (fn string) {
	// dbgo.Printf("%(red)%(LF)ConvetUrlToPath fnUrl=->%s<-\n", fnUrl)
	fnUrl = strings.Replace(fnUrl, "../", "", -1)
	fnUrl = strings.Replace(fnUrl, "./", "", -1)
	if len(fnUrl) > len(gCfg.ThumbnailPathURL) && strings.HasPrefix(fnUrl, gCfg.ImagePathURL) {
		// dbgo.Printf("%(red)%(LF)ConvetUrlToPath fnUrl=->%s<- %s\n", fnUrl, gCfg.ThumbnailPathURL)
		fn = fmt.Sprintf("./%s/%s", gCfg.ImagePath, fnUrl[len(gCfg.ImagePathURL):])
		fn = path.Clean(fn)
		// dbgo.Printf("%(red)%(LF)ConvetUrlToPath fn=->%s<-\n", fn)
	}
	return
}

func GenThumbnail(fns []string, width, height, owidth, oheight int, to string) error {

	if to == "" {
		to = gCfg.ThumbnailPath + "/dst.jpg"
	}

	// load images and make 100x100 thumbnails of them
	var thumbnails []image.Image
	max_h := 0
	var sh int
	for _, file := range fns {
		img, err := imaging.Open(file)
		if err != nil {
			if logger == nil {
				fields := []zapcore.Field{
					zap.String("message", "unable to open file for reading"),
					zap.String("file_name", file),
					zap.String("location", dbgo.LF()),
				}
				logger.Error("invalid-file", fields...)
			} else {
				fmt.Fprintf(logFilePtr, "Unable to open image for reading >%s< error:%s at:%s\n", file, err, dbgo.LF())
				fmt.Fprintf(os.Stderr, "%sUnable to open image for reading >%s< error:%s at:%s%s\n", dbgo.ColorRed, file, err, dbgo.LF(), dbgo.ColorReset)
			}
			return err
		}
		bounds := img.Bounds()
		w := bounds.Dx()
		h := bounds.Dy()
		sh = int(float32(h) / (float32(w) / float32(owidth)))
		if max_h < sh {
			max_h = sh
		}
		dbgo.Printf("%(red)%(LF) %s w=%d h=%d sh=%d factor=%v\n", file, w, h, sh, float32(w)/float32(owidth))
		// thumb := imaging.Thumbnail(img, width, height, imaging.CatmullRom)
		thumb := imaging.Resize(img, width, height, imaging.CatmullRom)
		thumbnails = append(thumbnails, thumb)
	}

	// create a new blank image
	//dst := imaging.New(owidth*len(thumbnails), oheight, color.NRGBA{0, 0, 0, 0})
	dst := imaging.New(owidth*len(thumbnails), sh, color.NRGBA{0, 0, 0, 0})

	// paste thumbnails into the new image side by side
	for i, thumb := range thumbnails {
		dst = imaging.Paste(dst, thumb, image.Pt(i*width, 0))
	}

	// save the combined image to file
	err := imaging.Save(dst, to)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error - Unable to save image: %s file:%s\n", err, to)
		return fmt.Errorf("Unable to save image %s - Error:%s", to, err)
	}
	return nil
}

// GetImageDimension returns width, height of an immage - .png, .jpg, .gif
//	- not working on .svg
//	- not returning errors
//
// Example:
//		h, w = GetHWFromImage ( ffile_name );
func GetImageDimension(imagePath string) (width int, height int) {
	file, err := os.Open(imagePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	defer file.Close()

	image, _, err := image.DecodeConfig(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", imagePath, err)
		return
	}
	return image.Width, image.Height
}

/* vim: set noai ts=4 sw=4: */
