package SetDefault

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"os"
	"reflect"
	"strconv"

	"github.com/fatih/structtag"
	"github.com/pschlump/dbgo"
)

// SetDefault set values based on 'default' tags in a struct.
func SetDefault(lCfg interface{}) (err error) {

	// Get the type and value of the argument we were passed.
	ptyp := reflect.TypeOf(lCfg)
	pval := reflect.ValueOf(lCfg)

	// Requries that lCfg is a pointer.
	if ptyp.Kind() != reflect.Ptr {
		err = fmt.Errorf("Must pass a address of a struct to ReadFile\n")
		return
	}

	var typ reflect.Type
	var val reflect.Value
	typ = ptyp.Elem()
	val = pval.Elem()

	// Create Defaults

	// Make sure we now have a struct
	if typ.Kind() != reflect.Struct {
		return fmt.Errorf("Not passed a struct.\n")
	}

	// Can we set values?
	if val.CanSet() {
		dbgo.DbPfb(db1, "Debug: We can set values.\n")
	} else {
		return fmt.Errorf("Passed a struct that will not allow setting of values\n")
	}

	// The number of fields in the struct is determined by the type of struct
	// it is. Loop through them.
	for i := 0; i < typ.NumField(); i++ {

		// Get the type of the field from the type of the struct. For a struct, you always get a StructField.
		sfld := typ.Field(i)

		// Get the type of the StructField, which is the type actually stored in that field of the struct.
		tfld := sfld.Type

		// Get the Kind of that type, which will be the underlying base type
		// used to define the type in question.
		kind := tfld.Kind()

		// Get the value of the field from the value of the struct.
		vfld := val.Field(i)
		tag := string(sfld.Tag)

		// ... and start using structtag by parsing the tag
		tags, err := structtag.Parse(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to parse structure tag ->%s<- %s\n", tag, err)
			os.Exit(1)
		}

		// Dump out what we've found
		if db1 {
			dbgo.Printf("Debug: struct field %d: name %s type %s kind %s value %v tag ->%s<- AT:%s\n", i, sfld.Name, tfld, kind, vfld, tag, dbgo.LF())

			// iterate over all tags
			for tn, t := range tags.Tags() {
				fmt.Printf("\t[%d] tag: %+v\n", tn, t)
			}

			// get a single tag
			defaultTag, err := tags.Get("default")
			if err != nil {
				fmt.Printf("`default` Not Set\n")
			} else {
				// Output: default:"foo,omitempty,string" Key: default Name: foo [omitempty string]
				fmt.Printf("defaultTag=[%s] Key=[%s] Name=[%s] Options=[%s]\n", defaultTag, defaultTag.Key, defaultTag.Name, defaultTag.Options)
				//fmt.Println(defaultTag)         // Output: default:"foo,omitempty,string"
				//fmt.Println(defaultTag.Key)     // Output: default
				//fmt.Println(defaultTag.Name)    // Output: foo
				//fmt.Println(defaultTag.Options) // Output: [omitempty string]
			}
		}

		defaultTag, err := tags.Get("default")
		// Is that field some kind of string, and is the value one we can set?
		if kind == reflect.String && vfld.CanSet() {
			dbgo.DbPfb(db33, "%sAT: %s%s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.ColorReset)
			if err != nil || defaultTag.Name == "" {
				// Ignore error - indicates no "default" tag set.
			} else {
				defaultValue := defaultTag.Name
				//func ProcessENV(curVal, sfldName string) string {
				if len(defaultValue) > 5 && defaultValue[0:5] == "$ENV$" {
					defaultValue = ProcessENV(defaultValue, sfld.Name)
				}
				dbgo.DbPfb(db1, "Debug: Looking to set field %s to a default value of ->%s<-\n", sfld.Name, defaultValue)
				vfld.SetString(defaultValue)
			}
		} else if (kind == reflect.Int || kind == reflect.Int64) && vfld.CanSet() {
			dbgo.DbPfb(db33, "%sAT: %s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
			if err != nil || defaultTag.Name == "" {
				// Ignore error - indicates no "default" tag set.
			} else {
				defaultValueStr := defaultTag.Name
				//func ProcessENV(curVal, sfldName string) string {
				if len(defaultValueStr) > 5 && defaultValueStr[0:5] == "$ENV$" {
					defaultValueStr = ProcessENV(defaultValueStr, sfld.Name)
				}
				defaultValue, err := strconv.ParseInt(defaultValueStr, 10, 64)
				if err != nil {
					return fmt.Errorf("Attempt to set default int value, invalid int ->%s<-, error [%s]", defaultValueStr, err)
				}
				dbgo.DbPfb(db1, "Debug: Looking to set field %s to a default value of ->%v<-\n", sfld.Name, defaultValue)
				vfld.SetInt(defaultValue)
			}
		} else if (kind == reflect.Uint || kind == reflect.Uint64) && vfld.CanSet() {
			dbgo.DbPfb(db33, "%sAT: %s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
			if err != nil || defaultTag.Name == "" {
				// Ignore error - indicates no "default" tag set.
			} else {
				defaultValueStr := defaultTag.Name
				if err != nil {
					return fmt.Errorf("Attempt to set default int value, invalid int ->%s<-, error [%s]", defaultValueStr, err)
				}
				//func ProcessENV(curVal, sfldName string) string {
				if len(defaultValueStr) > 5 && defaultValueStr[0:5] == "$ENV$" {
					defaultValueStr = ProcessENV(defaultValueStr, sfld.Name)
				}
				defaultValue, err := strconv.ParseInt(defaultValueStr, 10, 64)
				if err != nil {
					return fmt.Errorf("Attempt to set default int value, invalid int ->%s<-, error [%s]", defaultValueStr, err)
				}
				dbgo.DbPfb(db1, "Debug: Looking to set field %s to a default value of ->%v<-\n", sfld.Name, defaultValue)
				vfld.SetUint(uint64(defaultValue))
			}
		} else if kind == reflect.Bool && vfld.CanSet() {
			dbgo.DbPfb(db33, "%sAT: %s%s\n", dbgo.ColorCyan, dbgo.LF(), dbgo.ColorReset)
			if err != nil || defaultTag.Name == "" {
				// Ignore error - indicates no "default" tag set.
			} else {
				defaultValueStr := defaultTag.Name
				//func ProcessENV(curVal, sfldName string) string {
				if len(defaultValueStr) > 5 && defaultValueStr[0:5] == "$ENV$" {
					defaultValueStr = ProcessENV(defaultValueStr, sfld.Name)
				}
				defaultValue, err := strconv.ParseBool(defaultValueStr)
				if err != nil {
					return fmt.Errorf("Attempt to set default int value, invalid int ->%s<-, error [%s]", defaultValueStr, err)
				}
				dbgo.DbPfb(db1, "Debug: Looking to set field %s to a default value of ->%v<-\n", sfld.Name, defaultValue)
				vfld.SetBool(defaultValue)
			}
		} else if kind == reflect.Struct && vfld.CanSet() {
			dbgo.DbPfb(db33, "%sAT: %s%s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.ColorReset)
			recursiveChildStruct(vfld.Addr().Interface())
		} else if kind == reflect.Struct {
			dbgo.DbPfb(db33, "%sProbably an error - can not set - AT: %s%s\n", dbgo.ColorRed, dbgo.LF(), dbgo.ColorReset)
			err := fmt.Errorf("Passed a struct that can not be set")
			return err
		} else if kind != reflect.String && err == nil {
			dbgo.DbPfb(db33, "%sAT: %s%s\n", dbgo.ColorYellow, dbgo.LF(), dbgo.ColorReset)
			// report errors - defauilt is only implemented with strings.
			err := fmt.Errorf("default tag on struct is only implemented for `string`, `int`, `uint`, `int64`, `bool` fields in struct.  Fatal error on %s tag %s\n", sfld.Name, tag)
			return err
		}
	}
	return
}

var db1 = false
var db33 = false
