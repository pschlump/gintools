package run_template

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/filelib"
	"github.com/pschlump/ms"
	template "github.com/pschlump/textTemplate"
)

// var logFilePtr *os.File
var logFilePtr *os.File = os.Stdout

// - check that the template has all necessary named-temlates in it. (Function)
func ValidateTemplateHas(TemplateFn string, nameSet []string) (err error) {
	rtFuncMap := template.FuncMap{
		"Center":      ms.CenterStr,   //
		"PadR":        ms.PadOnRight,  //
		"PadL":        ms.PadOnLeft,   //
		"PicTime":     ms.PicTime,     //
		"FTime":       ms.StrFTime,    //
		"PicFloat":    ms.PicFloat,    //
		"nvl":         ms.Nvl,         //
		"Concat":      ms.Concat,      //
		"title":       strings.Title,  // The name "title" is what the function will be called in the template text.
		"ifDef":       ms.IfDef,       //
		"ifIsDef":     ms.IfIsDef,     //
		"ifIsNotNull": ms.IfIsNotNull, //
		// From: https://stackoverflow.com/questions/21482948/how-to-print-json-on-golang-template/21483211
		// "marshal": func(v interface{}) template.JS {
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			// return template.JS(a)
			return string(a)
		},
		"emptyList": func(v []string) bool {
			fmt.Fprintf(os.Stderr, "%s v=%s %s\n", dbgo.ColorRed, dbgo.SVarI(v), dbgo.ColorReset)
			if len(v) == 0 {
				return true
			} else {
				return false
			}
		},
	}

	t, err := template.New("simple-tempalte").Funcs(rtFuncMap).ParseFiles(TemplateFn)
	// t, err := template.New("simple-tempalte").ParseFiles(TemplateFn)
	if err != nil {
		fmt.Printf("Error(12004): parsing/reading template, %s, AT:%s\n", err, dbgo.LF())
		return fmt.Errorf("Error(12004): parsing/reading template, %s, AT:%s\n", err, dbgo.LF())
	}

	has := t.AvailableTemplates()
	if missing, ok := Contains(nameSet, has); !ok {
		return fmt.Errorf("Missing Template Items %s", missing)
	}
	return nil
}

func RunTemplateInlineString(TemplateBody string, g_data map[string]string) string {
	mdata := make(map[string]interface{})
	for k, v := range g_data {
		mdata[k] = v
	}
	return RunTemplateInline(TemplateBody, mdata)
}

func RunTemplateInline(TemplateBody string, g_data map[string]interface{}) string {

	rtFuncMap := template.FuncMap{
		"Center":      ms.CenterStr,   //
		"PadR":        ms.PadOnRight,  //
		"PadL":        ms.PadOnLeft,   //
		"PicTime":     ms.PicTime,     //
		"FTime":       ms.StrFTime,    //
		"PicFloat":    ms.PicFloat,    //
		"nvl":         ms.Nvl,         //
		"Concat":      ms.Concat,      //
		"title":       strings.Title,  // The name "title" is what the function will be called in the template text.
		"ifDef":       ms.IfDef,       //
		"ifIsDef":     ms.IfIsDef,     //
		"ifIsNotNull": ms.IfIsNotNull, //
		// From: https://stackoverflow.com/questions/21482948/how-to-print-json-on-golang-template/21483211
		// "marshal": func(v interface{}) template.JS {
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			// return template.JS(a)
			return string(a)
		},
		"emptyList": func(v []string) bool {
			fmt.Fprintf(os.Stderr, "%s v=%s %s\n", dbgo.ColorRed, dbgo.SVarI(v), dbgo.ColorReset)
			if len(v) == 0 {
				return true
			} else {
				return false
			}
		},
	}

	var b bytes.Buffer
	foo := bufio.NewWriter(&b)

	// xyzzy2000 - cache templates?

	t, err := template.New("inline").Funcs(rtFuncMap).Parse(TemplateBody)
	// t, err := template.New("simple-tempalte").ParseFiles(TemplateFn)
	if err != nil {
		fmt.Printf("Error(12004): parsing/reading template, ->%s<-, fn=[%s] AT:%s\n", err, TemplateBody, dbgo.LF())
		return ""
	}

	// check that the template has all necessary named-temlates in it. (Function)
	// func (t *Template) AvailableTemplates() (rv []string) {
	// has := t.AvailableTemplates()
	// if missing, ok := Contains(templateMethods, has); !ok {
	// 	fmt.Fprintf(os.Stderr, "Missing Template [%s] Items %s\n", TemplateFn, missing)
	// 	return ""
	// }

	err = t.ExecuteTemplate(foo, "inline", g_data)
	if err != nil {
		fmt.Fprintf(foo, "Error(12005): running template=%s, %s, AT:%s\n", TemplateBody, err, dbgo.LF())
		return ""
	}

	foo.Flush()
	s := b.String() // Fetch the data back from the buffer

	// fmt.Fprintf(os.Stdout, "Template Output is: ----->%s<----- AT: %s\n", s, dbgo.LF())

	return s
}

func RunTemplateInlineInterface(TemplateBody string, g_data interface{}) string {

	rtFuncMap := template.FuncMap{
		"Center":      ms.CenterStr,   //
		"PadR":        ms.PadOnRight,  //
		"PadL":        ms.PadOnLeft,   //
		"PicTime":     ms.PicTime,     //
		"FTime":       ms.StrFTime,    //
		"PicFloat":    ms.PicFloat,    //
		"nvl":         ms.Nvl,         //
		"Concat":      ms.Concat,      //
		"title":       strings.Title,  // The name "title" is what the function will be called in the template text.
		"ifDef":       ms.IfDef,       //
		"ifIsDef":     ms.IfIsDef,     //
		"ifIsNotNull": ms.IfIsNotNull, //
		// From: https://stackoverflow.com/questions/21482948/how-to-print-json-on-golang-template/21483211
		// "marshal": func(v interface{}) template.JS {
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			// return template.JS(a)
			return string(a)
		},
		"emptyList": func(v []string) bool {
			fmt.Fprintf(os.Stderr, "%s v=%s %s\n", dbgo.ColorRed, dbgo.SVarI(v), dbgo.ColorReset)
			if len(v) == 0 {
				return true
			} else {
				return false
			}
		},
	}

	var b bytes.Buffer
	foo := bufio.NewWriter(&b)

	// xyzzy2000 - cache templates?

	t, err := template.New("inline").Funcs(rtFuncMap).Parse(TemplateBody)
	// t, err := template.New("simple-tempalte").ParseFiles(TemplateFn)
	if err != nil {
		fmt.Printf("Error(12004): parsing/reading template, ->%s<-, fn=[%s] AT:%s\n", err, TemplateBody, dbgo.LF())
		return ""
	}

	// check that the template has all necessary named-temlates in it. (Function)
	// func (t *Template) AvailableTemplates() (rv []string) {
	// has := t.AvailableTemplates()
	// if missing, ok := Contains(templateMethods, has); !ok {
	// 	fmt.Fprintf(os.Stderr, "Missing Template [%s] Items %s\n", TemplateFn, missing)
	// 	return ""
	// }

	err = t.ExecuteTemplate(foo, "inline", g_data)
	if err != nil {
		fmt.Fprintf(foo, "Error(12005): running template=%s, %s, AT:%s\n", TemplateBody, err, dbgo.LF())
		return ""
	}

	foo.Flush()
	s := b.String() // Fetch the data back from the buffer

	// fmt.Fprintf(os.Stdout, "Template Output is: ----->%s<----- AT: %s\n", s, dbgo.LF())

	return s
}

func RunTemplateString(TemplateFn string, name_of string, g_data map[string]string) string {
	mdata := make(map[string]interface{})
	for k, v := range g_data {
		mdata[k] = v
	}
	return RunTemplate(TemplateFn, name_of, mdata)
}

// RunTemplate runs a template and get the results back as a string.
// This is the primary template runner for sending email.
func RunTemplate(TemplateFn string, name_of string, g_data map[string]interface{}) string {

	rtFuncMap := template.FuncMap{
		"Center":      ms.CenterStr,   //
		"PadR":        ms.PadOnRight,  //
		"PadL":        ms.PadOnLeft,   //
		"PicTime":     ms.PicTime,     //
		"FTime":       ms.StrFTime,    //
		"PicFloat":    ms.PicFloat,    //
		"nvl":         ms.Nvl,         //
		"Concat":      ms.Concat,      //
		"title":       strings.Title,  // The name "title" is what the function will be called in the template text.
		"ifDef":       ms.IfDef,       //
		"ifIsDef":     ms.IfIsDef,     //
		"ifIsNotNull": ms.IfIsNotNull, //
		// From: https://stackoverflow.com/questions/21482948/how-to-print-json-on-golang-template/21483211
		// "marshal": func(v interface{}) template.JS {
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			// return template.JS(a)
			return string(a)
		},
		"emptyList": func(v []string) bool {
			fmt.Fprintf(os.Stderr, "%s v=%s %s\n", dbgo.ColorRed, dbgo.SVarI(v), dbgo.ColorReset)
			if len(v) == 0 {
				return true
			} else {
				return false
			}
		},
	}

	var b bytes.Buffer
	foo := bufio.NewWriter(&b)

	// xyzzy2000 - cache templates?

	t, err := template.New("simple-tempalte").Funcs(rtFuncMap).ParseFiles(TemplateFn)
	// t, err := template.New("simple-tempalte").ParseFiles(TemplateFn)
	if err != nil {
		fmt.Printf("Error(12004): parsing/reading template, %s, fn=[%s] AT:%s\n", err, TemplateFn, dbgo.LF())
		return ""
	}

	// check that the template has all necessary named-temlates in it. (Function)
	// func (t *Template) AvailableTemplates() (rv []string) {
	// has := t.AvailableTemplates()
	// if missing, ok := Contains(templateMethods, has); !ok {
	// 	fmt.Fprintf(os.Stderr, "Missing Template [%s] Items %s\n", TemplateFn, missing)
	// 	return ""
	// }

	err = t.ExecuteTemplate(foo, name_of, g_data)
	if err != nil {
		fmt.Fprintf(foo, "Error(12005): running template=%s, %s, AT:%s\n", name_of, err, dbgo.LF())
		return ""
	}

	foo.Flush()
	s := b.String() // Fetch the data back from the buffer

	// fmt.Fprintf(os.Stdout, "Template Output is: ----->%s<----- AT: %s\n", s, dbgo.LF())

	return s

}

func ValidateTemplates(fns ...string) (rv bool) {
	rv = true
	for _, fn := range fns {
		if !filelib.Exists(fn) {
			fmt.Fprintf(os.Stderr, "%sMissing file %s%s\n", dbgo.ColorRed, fn, dbgo.ColorReset)
			fmt.Fprintf(logFilePtr, "Missing file %s\n", fn)
			rv = false
		}
	}
	return
}
