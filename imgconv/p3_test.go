package imgconv

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"
	"testing"
)

func Test_AllFiles(t *testing.T) {
	tests := []struct {
		pth          string
		mimeType     string
		expectedFile string
	}{
		{
			pth:          "./testdata/John-Paul-Jones.webp",
			mimeType:     "image/webp",
			expectedFile: "./testdata/John-Paul-Jones.png",
		},
		{
			pth:          "./testdata/438ae8ca48c0bf9646ea1968eed2f6fa.gif",
			mimeType:     "image/gif",
			expectedFile: "./testdata/438ae8ca48c0bf9646ea1968eed2f6fa.png",
		},
		{
			pth:          "./testdata/buffalo.jpg",
			mimeType:     "image/jpeg",
			expectedFile: "./testdata/buffalo.png",
		},
		{
			pth:          "./testdata/img_1280.heic",
			mimeType:     "image/heif",
			expectedFile: "./testdata/img_1280.png",
		},
		{
			pth:          "./testdata/code.html.pdf",
			mimeType:     "application/pdf",
			expectedFile: "./testdata/xyzzy",
		},
	}

	for ii, test := range tests {
		switch test.mimeType {
		case "image/webp":
			// func ConvWebpToPng(inputFn string) (fn string, err error) {
			fn, err := ConvWebpToPng(test.pth)
			if err != nil {
				t.Errorf("Error %2d, Unexpected error ->%s<-\n", ii, err)
			}
			if test.expectedFile != fn {
				t.Errorf("Error %2d, Unexpected file name ->%s<-\n", ii, fn)
			}
		case "image/gif":
			fn, err := ConvGifToPng(test.pth)
			if err != nil {
				t.Errorf("Error %2d, Unexpected error ->%s<-\n", ii, err)
			}
			if test.expectedFile != fn {
				t.Errorf("Error %2d, Unexpected file name ->%s<-\n", ii, fn)
			}
		case "image/jpeg":
			fn, err := ConvJpegToPng(test.pth)
			if err != nil {
				t.Errorf("Error %2d, Unexpected error ->%s<-\n", ii, err)
			}
			if test.expectedFile != fn {
				t.Errorf("Error %2d, Unexpected file name ->%s<-\n", ii, fn)
			}
		case "image/heif":
			//			fn, err := ConvHeicToPng(test.pth)
			//			if err != nil {
			//				t.Errorf("Error %2d, Unexpected error ->%s<-\n", ii, err)
			//			}
			//			if test.expectedFile != fn {
			//				t.Errorf("Error %2d, Unexpected file name ->%s<-\n", ii, fn)
			//			}
		case "application/pdf":
			ConvPdfToPngSetup("./cd-pdftoppm.sh", "./out", os.Stderr, nil)
			fns, dir, err := ConvPdfToPng(test.pth)
			if err != nil {
				t.Errorf("Error %2d, Unexpected error ->%s<-\n", ii, err)
			}
			//if test.expectedFile != fn {
			//	t.Errorf("Error %2d, Unexpected file name ->%s<-\n", ii, fn)
			//}
			fmt.Printf("fns=%s dir=%s\n", fns, dir)
		}
	}
}
