package awss3v2

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	//	"github.com/aws/aws-sdk-go/aws"
	//	"github.com/aws/aws-sdk-go/aws/awserr"
	//	"github.com/aws/aws-sdk-go/aws/session"
	//	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pschlump/dbgo"
)

type AwsS3Cfg struct {
	S3_Region            string `json:"aws_s3_region" default:"us-east-1"`
	S3_Bucket            string `json:"aws_s3_bucket" default:"a-document"`
	S3_Perms             string `json:"aws_s3_perms" default:"private"`
	AwsAccessKeyId       string `json:"AwsAccessKeyId" default:"$ENV$AWS_ACCESS_KEY_ID"`
	AwsSecretAccessKeyId string `json:"AwsSecretAccessKeyId" default:"$ENV$AWS_SECRET_ACCESS_KEY"`
}

var gCfg *AwsS3Cfg
var logFilePtr io.WriteCloser // var logFilePtr *os.File
var uploader *s3manager.Uploader
var downloader *s3manager.Downloader

func init() {
	logFilePtr = os.Stderr
}

// func ResetLogFile(newFp *os.File) {
func ResetLogFile(newFp io.WriteCloser) {
	logFilePtr = newFp
}

// func Setup(gcfg *AwsS3Cfg, lfp *os.File) (err error) {
func Setup(gcfg *AwsS3Cfg, lfp io.WriteCloser) (err error) {

	gCfg = gcfg
	logFilePtr = lfp

	uploader, err = NewUploader()
	if err != nil {
		dbgo.Fprintf(logFilePtr, "Error :%s on setup of S3 at:%(LF)\n", err)
		return
	}

	downloader, err = NewDownloader()
	if err != nil {
		dbgo.Fprintf(logFilePtr, "Error :%s on setup of S3 at:%(LF)\n", err)
		return
	}
	return
}

func NewDownloader() (downloader *s3manager.Downloader, err error) {

	KeyID := gCfg.AwsAccessKeyId
	SecretKey := gCfg.AwsSecretAccessKeyId

	if KeyID == "" || SecretKey == "" {
		fmt.Fprintf(os.Stderr, "Must setup environtmnt, source ~/.secret/setup.sh or set in cfg.json\n")
		return nil, fmt.Errorf("Missing configuration")
	}

	s3Config := &aws.Config{
		Region:      aws.String(gCfg.S3_Region),
		Credentials: credentials.NewStaticCredentials(KeyID, SecretKey, ""),
	}

	s3Session := session.New(s3Config)

	downloader = s3manager.NewDownloader(s3Session)
	return

}

func NewUploader() (uploader *s3manager.Uploader, err error) {

	KeyID := gCfg.AwsAccessKeyId
	SecretKey := gCfg.AwsSecretAccessKeyId

	if KeyID == "" || SecretKey == "" {
		fmt.Fprintf(os.Stderr, "Must setup environtmnt, source ~/.secret/setup.sh\n")
		return nil, fmt.Errorf("Missing configuration")
	}

	s3Config := &aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: credentials.NewStaticCredentials(KeyID, SecretKey, ""),
	}

	s3Session := session.New(s3Config)

	uploader = s3manager.NewUploader(s3Session)
	return
}

func DownloadFile(bucketName, key, outFile string) error {
	file, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = downloader.Download(
		file,
		&s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		},
	)
	return err
}

func UploadFile(bucketName, localFileName, s3FileName string) (err error) {
	file, err := ioutil.ReadFile(localFileName)
	if err != nil {
		return err
	}

	upInput := &s3manager.UploadInput{
		Bucket:      aws.String(bucketName),   // bucket's name
		Key:         aws.String(s3FileName),   // files destination location
		Body:        bytes.NewReader(file),    // content of the file
		ContentType: aws.String("text/plain"), // content type
	}
	res, err := uploader.UploadWithContext(context.Background(), upInput)
	// log.Printf("res %+v\n", res)
	fmt.Fprintf(logFilePtr, "%(LF) Upload %s to %s in bucket %s: Results: %s\n", localFileName, s3FileName, bucketName, dbgo.SVar(res))
	if err != nil {
		fmt.Fprintf(logFilePtr, "Error: %+v uploading file\n", err)
	}
	return
}

// AddFileToS3 will upload a single file to S3, it will require a pre-built aws session
// and will set file info like content type and encryption on the uploaded file.
// func AddFileToS3(s *session.Session, localFileName, s3FileName string) error {
func AddFileToS3(localFileName, s3FileName string) error {

	return UploadFile(gCfg.S3_Bucket, localFileName, s3FileName)

	// OLD	// Open the file for use
	// OLD	file, err := os.Open(localFileDir)
	// OLD	if err != nil {
	// OLD		return err
	// OLD	}
	// OLD	defer file.Close()
	// OLD
	// OLD	// Get file size and read the file content into a buffer
	// OLD	fileInfo, err := file.Stat()
	// OLD	if err != nil {
	// OLD		return err
	// OLD	}
	// OLD	var size int64 = fileInfo.Size()
	// OLD	if dbgo.IsDbOn("awss3-show-size") {
	// OLD		fmt.Printf("size=%d\n", size)
	// OLD	}
	// OLD	buffer := make([]byte, size)
	// OLD	_, err = file.Read(buffer)
	// OLD	if err != nil {
	// OLD		return err
	// OLD	}
	// OLD
	// OLD	// Config settings: this is where you choose the bucket, filename, content-type etc.  of the file you're uploading.
	// OLD	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
	// OLD		Bucket: aws.String(gCfg.S3_Bucket),
	// OLD		Key:    aws.String(fileDir),
	// OLD		//		ACL:                  aws.String(gCfg.S3_Perms),
	// OLD		Body:                 bytes.NewReader(buffer),
	// OLD		ContentLength:        aws.Int64(size),
	// OLD		ContentType:          aws.String(http.DetectContentType(buffer)),
	// OLD		ContentDisposition:   aws.String("attachment"),
	// OLD		ServerSideEncryption: aws.String("AES256"),
	// OLD	})
	// OLD	return err
}

// AddFileToS3ACL will upload a single file to S3, it will require a pre-built aws session
// and will set file info like content type and encryption on the uploaded file.
//
// perm must be "public-read" or "private".
func AddFileToS3ACL(localFileName, s3FileName, perm string) error {

	return UploadFile(gCfg.S3_Bucket, localFileName, s3FileName)

	//OLD	//if perm == "public-read" || perm == "private" {
	//OLD	//} else {
	//OLD	//	return fmt.Errorf("Invalid value for 'perm' is %s - should be 'public' or 'private'", perm)
	//OLD	//}
	//OLD
	//OLD	// Open the file for use
	//OLD	file, err := os.Open(localFileDir)
	//OLD	if err != nil {
	//OLD		return err
	//OLD	}
	//OLD	defer file.Close()
	//OLD
	//OLD	// Get file size and read the file content into a buffer
	//OLD	fileInfo, err := file.Stat()
	//OLD	if err != nil {
	//OLD		return err
	//OLD	}
	//OLD	var size int64 = fileInfo.Size()
	//OLD	if dbgo.IsDbOn("awss3-show-size") {
	//OLD		fmt.Printf("size=%d\n", size)
	//OLD	}
	//OLD	buffer := make([]byte, size)
	//OLD	_, err = file.Read(buffer)
	//OLD	if err != nil {
	//OLD		return err
	//OLD	}
	//OLD
	//OLD	if perm == "" {
	//OLD		perm = gCfg.S3_Perms
	//OLD	}
	//OLD
	//OLD	// Config settings: this is where you choose the bucket, filename, content-type etc.  of the file you're uploading.
	//OLD	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
	//OLD		Bucket:               aws.String(gCfg.S3_Bucket),
	//OLD		Key:                  aws.String(fileDir),
	//OLD		ACL:                  aws.String(perm),
	//OLD		Body:                 bytes.NewReader(buffer),
	//OLD		ContentLength:        aws.Int64(size),
	//OLD		ContentType:          aws.String(http.DetectContentType(buffer)),
	//OLD		ContentDisposition:   aws.String("attachment"),
	//OLD		ServerSideEncryption: aws.String("AES256"),
	//OLD	})
	//OLD	return err

}

func AddFileToS3ACLBucket(bucket, localFileName, s3FileName, perm string) error {

	return UploadFile(bucket, localFileName, s3FileName)

	//OLD	//if perm == "public-read" || perm == "private" {
	//OLD	//} else {
	//OLD	//	return fmt.Errorf("Invalid value for 'perm' is %s - should be 'public' or 'private'", perm)
	//OLD	//}
	//OLD
	//OLD	// Open the file for use
	//OLD	file, err := os.Open(localFileDir)
	//OLD	if err != nil {
	//OLD		return err
	//OLD	}
	//OLD	defer file.Close()
	//OLD
	//OLD	// Get file size and read the file content into a buffer
	//OLD	fileInfo, err := file.Stat()
	//OLD	if err != nil {
	//OLD		return err
	//OLD	}
	//OLD	var size int64 = fileInfo.Size()
	//OLD	if dbgo.IsDbOn("awss3-show-size") {
	//OLD		fmt.Printf("size=%d\n", size)
	//OLD	}
	//OLD	buffer := make([]byte, size)
	//OLD	_, err = file.Read(buffer)
	//OLD	if err != nil {
	//OLD		return err
	//OLD	}
	//OLD
	//OLD	if perm == "" {
	//OLD		perm = gCfg.S3_Perms
	//OLD	}
	//OLD
	//OLD	// Config settings: this is where you choose the bucket, filename, content-type etc.  of the file you're uploading.
	//OLD	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
	//OLD		Bucket:               aws.String(bucket), // Bucket:               aws.String(gCfg.S3_Bucket),
	//OLD		Key:                  aws.String(fileDir),
	//OLD		ACL:                  aws.String(perm),
	//OLD		Body:                 bytes.NewReader(buffer),
	//OLD		ContentLength:        aws.Int64(size),
	//OLD		ContentType:          aws.String(http.DetectContentType(buffer)),
	//OLD		ContentDisposition:   aws.String("attachment"),
	//OLD		ServerSideEncryption: aws.String("AES256"),
	//OLD	})
	//OLD	return err

}

func GetS3FileFromS3(to, bucket, s3fn string) error {

	return DownloadFile(bucket, s3fn, to)

	//OLD	// svc := s3.New(session.New())
	//OLD	input := &s3.GetObjectInput{
	//OLD		Bucket: aws.String(bucket),
	//OLD		Key:    aws.String(s3fn),
	//OLD	}
	//OLD
	//OLD	// result, err := svc.GetObject(input)
	//OLD	result, err := s3.New(s).GetObject(input)
	//OLD	if err != nil {
	//OLD		if aerr, ok := err.(awserr.Error); ok {
	//OLD			switch aerr.Code() {
	//OLD			case s3.ErrCodeNoSuchKey:
	//OLD				fmt.Println(s3.ErrCodeNoSuchKey, aerr.Error())
	//OLD			case s3.ErrCodeInvalidObjectState:
	//OLD				fmt.Println(s3.ErrCodeInvalidObjectState, aerr.Error())
	//OLD			default:
	//OLD				fmt.Println(aerr.Error())
	//OLD			}
	//OLD		} else {
	//OLD			// Print the error, cast err to awserr.Error to get the Code and
	//OLD			// Message from an error.
	//OLD			fmt.Println(err.Error())
	//OLD		}
	//OLD		return
	//OLD	}
	//OLD
	//OLD	// fmt.Println(result)
	//OLD
	//OLD	// err = ioutil.WriteFile(to, []byte(fmt.Sprintf("%s", result)), 0644)
	//OLD	err = ioutil.WriteFile(to, []byte(result.String()), 0644)
	//OLD	return

}

func IsSetup() bool {
	if uploader != nil {
		return true
	}
	return false
}

/* vim: set noai ts=4 sw=4: */
