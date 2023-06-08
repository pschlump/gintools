package main

// FRom: https://www.socketloop.com/tutorials/golang-generate-thumbnails-from-images

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"os"

	"github.com/disintegration/imaging"
	"github.com/pschlump/ReadConfig"
)

// "runtime"

type GlobalConfigData struct {
	ImageDir string `json:"image_dir" default:"./"`
	ThumbDir string `json:"thumb_dir" default:"./"`
}

// NIterations is the number of iterations that pbkdf2 hasing will use
const NIterations = 25000

var gCfg GlobalConfigData

var Cfg = flag.String("cfg", "cfg.json", "config file for this call")
var H = flag.Int("h", 100, "Height")
var W = flag.Int("w", 100, "Width")
var OH = flag.Int("oh", 100, "Output Height")
var OW = flag.Int("ow", 100, "Output Width")

func main() {
	// use all CPU cores for maximum performance
	// runtime.GOMAXPROCS(runtime.NumCPU())

	// "cfg.json"
	flag.Parse() // Parse CLI arguments to this, --cfg <name>.json

	fns := flag.Args() // input files

	if Cfg == nil {
		fmt.Printf("--cfg is a required parameter\n")
		os.Exit(1)
	}

	// ------------------------------------------------------------------------------
	// Read in Configuration
	// ------------------------------------------------------------------------------
	err := ReadConfig.ReadFile(*Cfg, &gCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read confguration: %s error %s\n", *Cfg, err)
		os.Exit(1)
	}

	GenThumbnail(fns, *W, *H, *OW, *OH, "dst.jpg")
}

func GenThumbnail(fns []string, width, height, owidth, oheight int, to string) error {

	if to == "" {
		to = "dst.jpg"
	}

	// load images and make 100x100 thumbnails of them
	var thumbnails []image.Image
	for _, file := range fns {
		img, err := imaging.Open(file)
		if err != nil {
			panic(err)
		}
		// thumb := imaging.Thumbnail(img, width, height, imaging.CatmullRom)
		thumb := imaging.Resize(img, width, height, imaging.CatmullRom)
		thumbnails = append(thumbnails, thumb)
	}

	// create a new blank image
	dst := imaging.New(owidth*len(thumbnails), oheight, color.NRGBA{0, 0, 0, 0})

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

	fmt.Printf("%s -> %s\n", fns, to)
	return nil
}
