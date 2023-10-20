package awss3v2

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

/*
from https://golangcode.com/uploading-a-file-to-s3/

Uploading a File to AWS S3

This example shows how to upload a local file onto an S3 bucket using the Go AWS SDK. Our first step is to step up the
session using the NewSession function. We’ve then created an AddFileToS3 function which can be called multiple times
when wanting to upload many files.

Within the PutObjectInput you can specify options when uploading the file and in our example we show how you can enable
AES256 encryption on your files (when at rest).

For this to work you’ll need to have your AWS credentials setup (with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY) and
you’ll need to fill in the S3_REGION and S3_BUCKET constants (More info on bucket regions here).
*/

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pschlump/dbgo"
)

type AwsS3Cfg struct {
	S3_Region string `json:"aws_s3_region" default:"us-east-1"`
	S3_Bucket string `json:"aws_s3_bucket" default:"a-document"`
	S3_Perms  string `json:"aws_s3_perms" default:"private"`
}

var gCfg *AwsS3Cfg
var logFilePtr *os.File

func init() {
	logFilePtr = os.Stderr
}

func Setup(gcfg *AwsS3Cfg, lfp *os.File) (s *session.Session, err error) {

	gCfg = gcfg
	logFilePtr = lfp

	dbgo.DbFprintf("AwsS3.config", os.Stderr, "gCfg >%s< bucket >%s< at:%s\n", dbgo.SVarI(gCfg), gCfg.S3_Bucket, dbgo.LF())

	// Create a single AWS session (we can re use this if we're uploading many files)
	s, err = session.NewSession(&aws.Config{Region: aws.String(gCfg.S3_Region)})
	if err != nil {
		fmt.Fprintf(logFilePtr, "Error :%s on setup of S3 at:%s\n", err, dbgo.LF())
		return
	}
	return
}

// AddFileToS3 will upload a single file to S3, it will require a pre-built aws session
// and will set file info like content type and encryption on the uploaded file.
func AddFileToS3(s *session.Session, localFileDir, fileDir string) error {

	// Open the file for use
	file, err := os.Open(localFileDir)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size and read the file content into a buffer
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	var size int64 = fileInfo.Size()
	if dbgo.IsDbOn("awss3-show-size") {
		fmt.Printf("size=%d\n", size)
	}
	buffer := make([]byte, size)
	_, err = file.Read(buffer)
	if err != nil {
		return err
	}

	// Config settings: this is where you choose the bucket, filename, content-type etc.  of the file you're uploading.
	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(gCfg.S3_Bucket),
		Key:                  aws.String(fileDir),
		ACL:                  aws.String(gCfg.S3_Perms),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(size),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})
	return err
}

// AddFileToS3ACL will upload a single file to S3, it will require a pre-built aws session
// and will set file info like content type and encryption on the uploaded file.
//
// perm must be "public-read" or "private".
func AddFileToS3ACL(s *session.Session, localFileDir, fileDir, perm string) error {

	//if perm == "public-read" || perm == "private" {
	//} else {
	//	return fmt.Errorf("Invalid value for 'perm' is %s - should be 'public' or 'private'", perm)
	//}

	// Open the file for use
	file, err := os.Open(localFileDir)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size and read the file content into a buffer
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	var size int64 = fileInfo.Size()
	if dbgo.IsDbOn("awss3-show-size") {
		fmt.Printf("size=%d\n", size)
	}
	buffer := make([]byte, size)
	_, err = file.Read(buffer)
	if err != nil {
		return err
	}

	if perm == "" {
		perm = gCfg.S3_Perms
	}

	// Config settings: this is where you choose the bucket, filename, content-type etc.  of the file you're uploading.
	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(gCfg.S3_Bucket),
		Key:                  aws.String(fileDir),
		ACL:                  aws.String(perm),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(size),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})
	return err
}

func AddFileToS3ACLBucket(s *session.Session, bucket, localFileDir, fileDir, perm string) error {

	//if perm == "public-read" || perm == "private" {
	//} else {
	//	return fmt.Errorf("Invalid value for 'perm' is %s - should be 'public' or 'private'", perm)
	//}

	// Open the file for use
	file, err := os.Open(localFileDir)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size and read the file content into a buffer
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	var size int64 = fileInfo.Size()
	if dbgo.IsDbOn("awss3-show-size") {
		fmt.Printf("size=%d\n", size)
	}
	buffer := make([]byte, size)
	_, err = file.Read(buffer)
	if err != nil {
		return err
	}

	if perm == "" {
		perm = gCfg.S3_Perms
	}

	// Config settings: this is where you choose the bucket, filename, content-type etc.  of the file you're uploading.
	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(bucket), // Bucket:               aws.String(gCfg.S3_Bucket),
		Key:                  aws.String(fileDir),
		ACL:                  aws.String(perm),
		Body:                 bytes.NewReader(buffer),
		ContentLength:        aws.Int64(size),
		ContentType:          aws.String(http.DetectContentType(buffer)),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
	})
	return err
}

func GetS3FileFromS3(s *session.Session, to, bucket, s3fn string) (err error) {

	// svc := s3.New(session.New())
	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(s3fn),
	}

	// result, err := svc.GetObject(input)
	result, err := s3.New(s).GetObject(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchKey:
				fmt.Println(s3.ErrCodeNoSuchKey, aerr.Error())
			case s3.ErrCodeInvalidObjectState:
				fmt.Println(s3.ErrCodeInvalidObjectState, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	// fmt.Println(result)

	// err = ioutil.WriteFile(to, []byte(fmt.Sprintf("%s", result)), 0644)
	err = ioutil.WriteFile(to, []byte(result.String()), 0644)
	return

}

func ResetLogFile(newFp *os.File) {
	logFilePtr = newFp
}

/* vim: set noai ts=4 sw=4: */
