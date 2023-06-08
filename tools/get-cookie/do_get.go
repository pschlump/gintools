package main

// File is BSD 3 clause and MIT Licensed.
// Copyrgit (C) Philip Schlump, 2017.

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pschlump/dbgo"
)

type HeaderType struct {
	Name  string
	Value string
}

var GetTimeout = 10

func DoGetHeader(uri string, hdr []HeaderType, args ...string) (status int, rv string) {

	sep := "?"
	var qq bytes.Buffer
	qq.WriteString(uri)
	for ii := 0; ii < len(args); ii += 2 {
		// q = q + sep + name + "=" + value;
		qq.WriteString(sep)
		qq.WriteString(url.QueryEscape(args[ii]))
		qq.WriteString("=")
		if ii+1 < len(args) {
			qq.WriteString(url.QueryEscape(args[ii+1]))
		}
		sep = "&"
	}
	url_q := qq.String()

	// res, err := http.Get(url_q)
	if DbOn["DoGet"] {
		fmt.Printf("%sRequest: ->%s<-%s\n", dbgo.ColorCyan, url_q, dbgo.ColorReset)
	}

	timeout := time.Duration(time.Duration(GetTimeout) * time.Second)
	client := &http.Client{
		Timeout: timeout,
	}
	req, err := http.NewRequest("GET", url_q, nil)
	req.Header.Add("User-Agent", "load2fa")
	for _, hh := range hdr {
		req.Header.Add(hh.Name, hh.Value)
	}
	// req.Header.Add("X-Qr-Auth", "w4h0wvtb1zk4uf8Xv.Ns9Q7j8") // Xyzzy - set from config?
	res, err := client.Do(req)

	if err != nil {
		if DbOn["DoGet"] {
			fmt.Printf("%sError: %s AT:%s%s\n", dbgo.ColorCyan, err, dbgo.LF(2), dbgo.ColorReset)
		}
		// xyzzyError
		return 500, ""
	} else {
		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			if DbOn["DoGet"] {
				fmt.Printf("%sError: %s AT:%s%s\n", dbgo.ColorCyan, err, dbgo.LF(2), dbgo.ColorReset)
			}
			// xyzzyError
			return 500, ""
		}
		status = res.StatusCode
		if status == 200 {
			rv = string(body)
		}
		if DbOn["DoGet"] {
			contentType := res.Header.Get("Content-Type")
			fmt.Printf("ContentType: [%s]\n", contentType)
			if strings.HasPrefix(contentType, "image/") {
				fmt.Printf("%simage: len(%d)%s\n\n", dbgo.ColorCyan, len(rv), dbgo.ColorReset)
			} else if len(rv) > 512 {
				fmt.Printf("%sbody: %s ....... %s\n\n", dbgo.ColorCyan, rv[0:512], dbgo.ColorReset)
			} else {
				fmt.Printf("%sbody: %s%s\n\n", dbgo.ColorCyan, rv, dbgo.ColorReset)
			}
		}
		return
	}
}
