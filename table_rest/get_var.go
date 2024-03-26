package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pschlump/HashStrings"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/gintools/log_enc"
	"github.com/pschlump/mapstructure"
	"github.com/pschlump/uuid"
)

// log_enc.LogStoredProcError(c, stmt, "ee!ee!!", SVar(RegisterResp), pp.Email, pp.Validator /*gCfg.EncryptionPassword,*/, pp.FirstName, pp.LastName /*, gCfg.UserdataPassword*/, secret) // xyzzy - Encrypted Log File Data

func ParseAllParams(c *gin.Context) (rv map[string]string, err error) {

	content_type := c.Request.Header.Get("Content-Type")
	content_type = strings.ToLower(content_type)
	method := c.Request.Method

	if false {
		if (method == "POST" || method == "PUT") && strings.HasPrefix(content_type, "application/json") {

			body, e0 := ioutil.ReadAll(c.Request.Body)
			dbgo.Printf("%(magenta) body ->%s<- %(LF)\n", body)
			if e0 != nil {
				err = e0
				return
			}
			t := make(map[string]string)
			e0 = json.Unmarshal(body, &t)
			if e0 != nil {
				err = e0
				return
			}
			if vv, found := t["__method__"]; found {
				if InArray(vv, []string{"GET", "PUT", "POST", "DELETE", "PATCH"}) {
					SetValue(c, "__orig_method__", c.Request.Method)
					c.Request.Method = vv
				}
			}
			fmt.Printf("JSON Request ->%s<-\n", dbgo.SVar(t))
			for name, val := range t {
				SetValue(c, name, val)
			}

		} else {

			// var ss struct{}
			// c.Bind(ss)

			c.Request.ParseForm()
			dbgo.Fprintf(os.Stderr, "%(cyan)%(LF) -- should parse body -- ContentType = %s c/context=%s\n", content_type, dbgo.SVarI(c))

			if len(c.Request.Form) > 0 {
				for key, val := range c.Request.Form {
					if len(val) > 0 {
						dbgo.Printf("%(magenta) at:%(LF) name=->%s<- value=->%s<-  ---- %s\n", key, val, dbgo.LF(-2))
						c.Set(key, val[0])
					}
				}
			}
			if len(c.Request.PostForm) > 0 {
				for key, val := range c.Request.PostForm {
					if len(val) > 0 {
						dbgo.Printf("%(magenta) at:%(LF) name=->%s<- value=->%s<-  ---- %s\n", key, val, dbgo.LF(-2))
						c.Set(key, val[0])
					}
				}
			}
			if c.Request.MultipartForm != nil && len(c.Request.MultipartForm.Value) > 0 {
				for key, val := range c.Request.MultipartForm.Value {
					if len(val) > 0 {
						dbgo.Printf("%(magenta) at:%(LF) name=->%s<- value=->%s<-  ---- %s\n", key, val, dbgo.LF(-2))
						c.Set(key, val[0])
					}
				}
			}
		}
	} else {

		var val string

		if c.Request.Method == "GET" || c.Request.Method == "DELETE" {
			// type Values map[string][]string
			keys := c.Request.URL.Query()
			for name := range keys {
				if len(keys[name]) == 1 {
					val = keys[name][0]
				} else {
					val = dbgo.SVar(keys[name])
				}
				c.Set(name, val)
			}
			if vv, found := keys["__method__"]; found && len(vv) >= 1 {
				if InArray(vv[0], []string{"GET", "PUT", "POST", "DELETE", "PATCH"}) {
					c.Set("__orig_method__", c.Request.Method)
					c.Request.Method = vv[0]
				}
			}
		} else if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			keys := c.Request.URL.Query()
			for name := range keys {
				if len(keys[name]) == 1 {
					val = keys[name][0]
				} else {
					val = dbgo.SVar(keys[name])
				}
				c.Set(name, val)
			}
			if vv, found := keys["__method__"]; found && len(vv) >= 1 {
				if InArray(vv[0], []string{"GET", "PUT", "POST", "DELETE", "PATCH"}) {
					c.Set("__orig_method__", c.Request.Method)
					c.Request.Method = vv[0]
				}
			}
			// r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			content_type := c.Request.Header.Get("Content-Type")
			content_type = strings.ToLower(content_type)
			if content_type == "" || strings.HasPrefix(content_type, "application/x-www-form-urlencoded") {
				if db94 {
					dbgo.Printf("%(yellow) found x-www-form-urlencoded header: AT:%(LF)\n")
				}
				c.Request.ParseForm()
				for name, xval := range c.Request.Form {
					if len(xval) == 1 {
						c.Set(name, xval[0])
					} else {
						c.Set(name, dbgo.SVar(xval))
					}
					if name == "__method__" {
						if InArray(xval[0], []string{"GET", "PUT", "POST", "DELETE", "PATCH"}) {
							c.Set("__orig_method__", c.Request.Method)
							c.Request.Method = xval[0]
						}
					}
				}

			} else if strings.HasPrefix(content_type, "application/json") {
				body, e0 := ioutil.ReadAll(c.Request.Body)
				dbgo.Printf("%(magenta) body ->%s<- err:%s %(LF)\n", body, e0)
				if e0 != nil {
					err = e0
					return
				}
				t := make(map[string]interface{})
				e0 = json.Unmarshal(body, &t)
				if e0 != nil {
					err = e0
					return
				}
				tPrime := make(map[string]string)
				for k, v := range t {
					tPrime[k] = fmt.Sprintf("%v", v)
				}
				dbgo.Printf("%(magenta) %(LF) t=%s tPrime=%s\n", dbgo.SVarI(t), dbgo.SVarI(tPrime))
				if vv, found := tPrime["__method__"]; found {
					if InArray(vv, []string{"GET", "PUT", "POST", "DELETE", "PATCH"}) {
						c.Set("__orig_method__", c.Request.Method)
						c.Request.Method = vv
					}
				}
				fmt.Printf("JSON Request ->%s<-\n", dbgo.SVar(t))
				for name, val := range tPrime {
					c.Set(name, val)
				}

			} else if strings.HasPrefix(content_type, "multipart/form-data") {

				err = c.Request.ParseMultipartForm(2 << 21) // 20MB
				if err != nil {
					http.Error(c.Writer, "failed to parse multipart message", http.StatusBadRequest)
					return
				}

				// https://ayada.dev/posts/multipart-requests-in-go/
				/*
					This is what gets parsed.  Name/Value are in Value
						type Form struct {
							Value map[string][]string
							File  map[string][]*FileHeader
						}
					c.Request.MultipartForm.Value["name"]
				*/

				dbgo.DbPrintf("ParseAllParams.FileUpload", "%(cyan)AT:%(LF) parse results of multipart/form-data\nreq.MultipartForm=%s\n", dbgo.SVarI(c.Request.MultipartForm))
				for name, val := range c.Request.MultipartForm.Value {
					if len(val) > 0 {
						c.Set(name, val[0])
					}
				}

				// See: https://golangbyexample.com/http-mutipart-form-body-golang/
				// has examples of "curl" to send files and test this stuff.

				// Save and process files - insert into d.b. header for file info - setup / return - of file data.

				fileDest := uCfg.UploadPath
				// 	URLUploadPath string `json:"url_upload_path" default:"/files"`

				fileList := make([]AnUploadedFile, 0, 10)

				//get the *fileheaders
				for xFileName, fileGroup := range c.Request.MultipartForm.File {
					_ = fileGroup
					dbgo.DbPrintf("ParseAllParams.FileUpload", "%(yellow)top of loop: for ->%s<- %T%(LF)\n", xFileName, xFileName)

					// files := c.Request.MultipartForm.File["multiplefiles"] // grab the filenames
					files := c.Request.MultipartForm.File[xFileName] // grab the filenames

					err = os.MkdirAll(fileDest, 0755)
					dbgo.DbPrintf("ParseAllParams.FileUpload", "%s %(LF)\n", err)

					dbgo.DbPrintf("ParseAllParams.FileUpload", "just before loop: %(LF)\n")
					for i, _ := range files { // loop through the files one by one
						dbgo.Printf("At top of files loop: %(LF)\n")
						file, err0 := files[i].Open()
						defer file.Close()
						if err0 != nil {
							fmt.Fprintln(c.Writer, err0)
							return
						}

						dbgo.DbPrintf("ParseAllParams.FileUpload", "%(LF)\n")
						uuid := GenUUID()
						dbgo.DbPrintf("ParseAllParams.FileUpload", "uuid=%s: %(LF)\n", uuid)
						// out, err0 := os.Create(path.Join(fileDest, files[i].Filename))
						fn := path.Join(fileDest, uuid)
						out, err0 := filelib.Fopen(fn, "w")
						if err0 != nil {
							fmt.Fprintf(c.Writer, "Unable to create the file for writing. Check your write access privilege.")
							dbgo.Fprintf(os.Stderr, "Unable to create the file for writing. File:%s Error:%s at:%(LF)\n", fn, err0)
							return
						}

						dbgo.DbPrintf("ParseAllParams.FileUpload", "%(LF)\n")
						_, err0 = io.Copy(out, file) // file not files[i] !
						if err0 != nil {
							fmt.Fprintf(c.Writer, "Error: %s\n", err0)
							dbgo.Fprintf(os.Stderr, "Error: %s at:%(LF)\n", err0)
							out.Close()
							return
						}
						out.Close()

						dbgo.DbPrintf("ParseAllParams.FileUpload", "%(LF)\n")
						dbgo.Fprintf(c.Writer, "Files uploaded successfully : uuid=%s : filenam=%s\n", uuid, files[i].Filename+"\n")
						dbgo.Fprintf(os.Stderr, "Files uploaded successfully : uuid=%s : filenam=%s at:%(LF)\n", uuid, files[i].Filename+"\n")

						// 0. Hash each file and create link from UUID to hash value of file
						hash, err0 := HashStrings.HashFile(fn)
						if err0 != nil {
							fmt.Fprintf(c.Writer, "Error: %s\n", err0)
							dbgo.Fprintf(os.Stderr, "Error: %s at:%(LF)\n", err0)
							return
						}

						// link to Hash of Self
						// 0. Hash each file and create link from UUID to hash value of file - xyzzy421 (((( Implemented, not tested ))))
						newpath := path.Join(fileDest, hash)
						if filelib.Exists(newpath) {
							// should we link?
							// should we link? Yes
							// TODO - should we link? Yes
							// should we link? Yes
							// should we link?
						} else {
							if err0 = os.Link(fn, newpath); err != nil {
								fmt.Fprintf(c.Writer, "Warning: %s\n", err0)
								dbgo.Fprintf(os.Stderr, "Warning: %s at:%(LF)\n", err0)
								return
							}
						}

						// aws_file_name := hash

						// 						// push file to AWS S3
						// 						if gCfg.PushToAWS == "yes" {
						//
						// 							if awsSession == nil {
						// 								fmt.Fprintf(os.Stderr, "\n%sAT: %s Error - Failed to setup AWS correctly - and trying to push file to AWS/S3%s\n\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
						// 								fmt.Fprintf(logFilePtr, "\n%sAT: %s Error - Failed to setup AWS correctly - and trying to push file to AWS/S3%s\n\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
						// 							} else {
						//
						// 								go func(x_file_name, x_aws_file_name string) {
						// 									fmt.Printf("%sAT: %s%s\n", dbgo.ColorMagenta, dbgo.LF(), dbgo.ColorReset)
						// 									if dbgo.IsDbOn("Upload.01") {
						// 										fmt.Printf("AT: %s\n", dbgo.LF())
						// 										fmt.Fprintf(os.Stderr, "%s Will attempt to upload to S3: AT: %s %s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
						// 									}
						// 									err = awss3v2.AddFileToS3ACL(awsSession, x_file_name, x_aws_file_name, gCfg.S3Perms)
						// 									if err != nil {
						// 										fmt.Printf("%sAT: %s%s\n", dbgo.ColorMagenta, dbgo.LF(), dbgo.ColorReset)
						// 										fmt.Fprintf(os.Stderr, "\n%sAT: %s Error - Failed  AWS/S3 -- %s %s\n\n", dbgo.ColorRed, dbgo.LF(), err, dbgo.ColorReset)
						// 										fmt.Fprintf(logFilePtr, "\n%sAT: %s Error - Failed  AWS/S3 -- %s %s\n\n", dbgo.ColorRed, dbgo.LF(), err, dbgo.ColorReset)
						// 										data.ErrorReturn(c, logFilePtr, data.RequestError{
						// 											Status:        http.StatusBadRequest, // 406
						// 											ClientMessage: "Failed to push file to AWS/S3.",
						// 										})
						// 										return
						// 									}
						// 									//}(file_name, aws_file_name)
						// 								}(fn, aws_file_name)
						//
						// 							}
						// 						}

						fileList = append(fileList, AnUploadedFile{
							Id:               uuid,
							OriginalFileName: files[i].Filename,
							FileHash:         hash,
						})

						dbgo.DbPrintf("ParseAllParams.FileUpload", "%(LF)\n")
						content_type := "plain/text"
						if hdr := files[i].Header; len(hdr) > 0 {
							if content_type0, ok := hdr["Content-Type"]; ok {
								if len(content_type0) > 0 {
									content_type = content_type0[0]
								}
							}
						}

						//	0. Upload files to S3 - xyzzy422
						// xyzzy - TODO - Save the file to AWS
						// insert into q_qr_file_uploaded ( ... )
						/*
							-- new apr-25 --
							CREATE TABLE if not exists q_qr_uploaded_files (
								id					uuid DEFAULT uuid_generate_v4() not null primary key,
								group_id			uuid,				-- a user specified ID to join to anotehr table.
								group_n_id			int,
								original_file_name	text not null,
								content_type		text not null default 'text/plain',
								size 				int not null default 0,
								file_hash			text,
								url_path			text,
								local_file_path		text
							);
						*/

						dbgo.DbPrintf("ParseAllParams.FileUpload", "content_type ->%s<- %(LF)\n", content_type)
						// found_n, group_n_id := GetVar("group_n_id", www, c.Request)
						// s_group_n := ""
						// n_group_n := ""
						// if found_n && group_n_id != "" {
						// }

						found, group_id := GetVar("group_id", c)
						// s_group := ""
						// n_group := ""
						if found && group_id != "" {
							// s_group, n_gorup = ", group_id", ", $6"
							// _, _ = s_group, n_gorup

							dbgo.DbPrintf("ParseAllParams.FileUpload", "%(LF)\n")
							stmt := "insert into q_qr_uploaded_files ( id, original_file_name, content_type, size, group_id, file_hash ) values ( $1, $2, $3, $4, $5, $6 )"
							res, err0 := conn.Exec(ctx, stmt, uuid, files[i].Filename, content_type, files[i].Size, group_id, hash)
							if err0 != nil {
								log_enc.LogSQLError(c, stmt, err0, uuid, files[i].Filename, content_type, files[i].Size, group_id, hash)
								return
							}
							_ = res
						} else {
							dbgo.DbPrintf("ParseAllParams.FileUpload", "%(LF)\n")
							stmt := "insert into q_qr_uploaded_files ( id, original_file_name, content_type, size, file_hash ) values ( $1, $2, $3, $4, $5 )"
							res, err0 := conn.Exec(ctx, stmt, uuid, files[i].Filename, content_type, files[i].Size, hash)
							if err0 != nil {
								log_enc.LogSQLError(c, stmt, err0, uuid, files[i].Filename, content_type, files[i].Size, hash)
								return
							}
							_ = res
						}

						dbgo.DbPrintf("ParseAllParams.FileUpload", "%(LF)\n")
					}
					dbgo.DbPrintf("ParseAllParams.FileUpload", "%(cyan)Outer Loop Bottom %(LF)\n")
				}
				dbgo.DbPrintf("ParseAllParams.FileUpload", "%(LF)\n")

				dbgo.DbPrintf("ParseAllParams.FileUpload", "Files Uploaded: %s\n", dbgo.SVarI(fileList))

				// xyzzy - Setup the __file_id_list__
				c.Set("__file_id_list__", dbgo.SVarI(fileList))

			} else {
				err = fmt.Errorf("invalid mime encoding format")
				http.Error(c.Writer, "invalid mime encoding format", http.StatusBadRequest)
				return
			}
		}
	}

	return
}

func GetVar(name string, c *gin.Context) (found bool, value string) {
	if len(name) > len("__$ENV$x") && name[0:len("__$ENV$")] == "__$ENV$" {
		// fmt.Printf("lookup ->%s<-\n", name[len("__$ENV$"):len(name)-2])
		env := os.Getenv(name[len("__$ENV$") : len(name)-2])
		if env != "" {
			return true, env
			// fmt.Printf("Found name= ->%s<- : ->%s<-\n", name, env)
			// return
		}
	}
	_, found = c.Keys[name]
	if !found {
		value = c.Param(name)
		if value != "" {
			c.Set(name, value)
			found = true
		}
	}
	if found {
		value = c.GetString(name)
	}
	// dbgo.Printf("%(red)GetVar %(LF) found=%v name=->%s<- value=->%s<-\n", found, name, value)
	return
}

func SetValue(c *gin.Context, name string, value string) {
	// dbgo.Printf("%(magenta) at:%(LF) name=->%s<- value=->%s<-  ---- %s\n", name, value, dbgo.LF(-2))
	c.Set(name, value)
}

func GetNameList(c *gin.Context) (names []string) {
	for name := range c.Keys {
		names = append(names, name)
	}
	return
}

func GenUUID() string {
	newUUID, _ := uuid.NewV4()
	return newUUID.String()
}

func copy_to_struct(from map[string]string, result interface{}) (unused []string, err error) {

	// This input can come from anywhere, but typically comes from
	// something like decoding JSON where we're not quite sure of the
	// struct initially.
	input := make(map[string]interface{})
	for k, v := range from {
		input[k] = v
	}

	// For metadata, we make a more advanced DecoderConfig so we can
	// more finely configure the decoder that is used. In this case, we
	// just tell the decoder we want to track metadata.
	var md mapstructure.Metadata
	// var result Person
	config := &mapstructure.DecoderConfig{
		Metadata: &md,
		Result:   result,
	}

	decoder, e0 := mapstructure.NewDecoder(config)
	if e0 != nil {
		err = e0
		dbgo.Printf("Error: %s at:%(LF)\n", err)
		return
	}

	if err = decoder.Decode(input); err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	fmt.Printf("Unused keys: %s\n", dbgo.SVarI(md.Unused))
	for k := range md.Unused {
		unused = append(unused, md.Unused[k])
	}
	// Output:
	// Unused keys: []string{"email"}
	fmt.Printf("Matched Data: %s\n", dbgo.SVarI(result))
	// Output:
	//

	return
}

type AnUploadedFile struct {
	OriginalFileName string
	Id               string
	FileHash         string
}

var db94 = false

/* vim: set noai ts=4 sw=4: */
