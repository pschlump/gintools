package table_rest

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"

	"github.com/pschlump/dbgo"
)

// IsBool returns true if one of the true/fals names
func IsBool(s string) (ok bool) {
	_, ok = boolValues[s]
	return
}

// IsHexNumber returns true if composed of Optional 0x|0X followd by 0..9 a..f A..F
func IsHexNumber(s string) (ok bool) {
	ok = isHexStringRe.MatchString(s)
	return
}

// IsNumber returns true if the string is composed of 0..0 digigts optionally with a +- at beginning.
func IsNumber(s string) (ok bool) {
	ok = isIntStringRe.MatchString(s)
	return
}

var isIntStringRe *regexp.Regexp
var isHexStringRe *regexp.Regexp
var trueValues map[string]bool
var boolValues map[string]bool

func init() {
	isIntStringRe = regexp.MustCompile("([+-])?[0-9][0-9]*")
	isHexStringRe = regexp.MustCompile("(0x)?[0-9a-fA-F][0-9a-fA-F]*")

	trueValues = make(map[string]bool)
	trueValues["t"] = true
	trueValues["T"] = true
	trueValues["yes"] = true
	trueValues["Yes"] = true
	trueValues["YES"] = true
	trueValues["1"] = true
	trueValues["true"] = true
	trueValues["True"] = true
	trueValues["TRUE"] = true
	trueValues["on"] = true
	trueValues["On"] = true
	trueValues["ON"] = true

	boolValues = make(map[string]bool)
	boolValues["t"] = true
	boolValues["T"] = true
	boolValues["yes"] = true
	boolValues["Yes"] = true
	boolValues["YES"] = true
	boolValues["1"] = true
	boolValues["true"] = true
	boolValues["True"] = true
	boolValues["TRUE"] = true
	boolValues["on"] = true
	boolValues["On"] = true
	boolValues["ON"] = true

	boolValues["f"] = true
	boolValues["F"] = true
	boolValues["no"] = true
	boolValues["No"] = true
	boolValues["NO"] = true
	boolValues["0"] = true
	boolValues["false"] = true
	boolValues["False"] = true
	boolValues["FALSE"] = true
	boolValues["off"] = true
	boolValues["Off"] = true
	boolValues["OFF"] = true
}

// IsIntString returns true if the string is composed of 0..0 digigts optionally with a +- at beginning.
func IsIntString(s string) bool {
	return isIntStringRe.MatchString(s)
}

// ParseBool convers a string to bool based on the table of trueValues.
func ParseBool(s string) (b bool) {
	_, b = trueValues[s]
	return
	//if InArray(s, []string{"t", "T", "yes", "Yes", "YES", "1", "true", "True", "TRUE", "on", "On", "ON"}) {
	//	return true
	//}
	//return false
}

// MaxFloat64 returns the maximum of 2 float64 values.
func MaxFloat64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// MinFloat64 returns the minimum of 2 float64 values.
func MinFloat64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// AbsFloat64 returns the absolute value.  Negatives are converted to positive.
func AbsFloat64(a float64) float64 {
	if a < 0 {
		return -a
	}
	return a
}

// BoolToYesNo convers a boolena to a Yes/No value.
func BoolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return " No"
}

// RoundToPennies generates a rouned to pennies value for a float64.
func RoundToPennies(f float64) float64 {
	return math.Round(f*100) / 100
}

// YearsToSeconds converts a number of years to seconds
func YearsToSeconds(yr float64) (sec float64) {
	sec = yr * 365.25 * 24 * 60 * 60
	return
}

// Round rouns a float64 to the nearest integer value.
func Round(input float64) float64 {
	if input < 0 {
		return math.Ceil(input - 0.5)
	}
	return math.Floor(input + 0.5)
}

// HalfLifeDecay xyzzy
func HalfLifeDecay(startValue float64, timeSpanInSeconds float64, halfLifeInSeconds float64) float64 {

	x := 2.0
	y := timeSpanInSeconds / halfLifeInSeconds

	value := startValue / math.Pow(x, y)

	// even if everything is gone(decayed)
	// the left over is still 1 mathematically and by physics law
	if value < 1 {
		value++
	}
	// value = round(value)
	value = RoundToPennies(value)
	return value
}

// Assert assumes that 'b' is true - if not the program will fail and exit.
func Assert(b bool) {
	if !b {
		fmt.Fprintf(os.Stderr, "%sFatal: Failed Assert: %s%s\n", dbgo.ColorRed, dbgo.LF(-2), dbgo.ColorReset)
		os.Exit(1)
	}
}

// KeysFromMap returns an array of keys from a map.
//
// This is used like this:
//
//	keys := KeysFromMap(nameMap)
//	sort.Strings(keys)
//	for _, key := range keys {
//		val := nameMap[key]
//		...
//	}
//
func KeysFromMap(a interface{}) (keys []string) {
	xkeys := reflect.ValueOf(a).MapKeys()
	keys = make([]string, len(xkeys))
	for ii, vv := range xkeys {
		keys[ii] = vv.String()
	}
	return
}

/* vim: set noai ts=4 sw=4: */
