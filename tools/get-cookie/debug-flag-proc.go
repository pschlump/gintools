package main

// Copyright (C) Philip Schlump, 2018.
// This file is BSD 3 Clause licensed.
// See ./LICENSE.bsd

import (
	"fmt"
	"os"
	"strings"

	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
)

// func LiveMonSetup(name string, db_flag map[string]bool, gCfg *BaseConfigType) {
func DebugFlagProcess(DbFlag *string, db_flag map[string]bool, gCfg *data.BaseConfigType) {
	if gCfg.DebugFlag != "" {
		ss := strings.Split(gCfg.DebugFlag, ",")
		// fmt.Printf("gCfg.DebugFlag ->%s<-\n", gCfg.DebugFlag)
		for _, sx := range ss {
			// fmt.Printf("Setting ->%s<-\n", sx)
			db_flag[sx] = true
		}
	}
	if *DbFlag != "" {
		ss := strings.Split(*DbFlag, ",")
		// fmt.Printf("gCfg.DebugFlag ->%s<-\n", gCfg.DebugFlag)
		for _, sx := range ss {
			// fmt.Printf("Setting ->%s<-\n", sx)
			db_flag[sx] = true
		}
	}
	if db_flag["dump-db-flag"] {
		fmt.Fprintf(os.Stderr, "%sDB Flags Enabled Are:%s\n", dbgo.ColorGreen, dbgo.ColorReset)
		for x := range db_flag {
			fmt.Fprintf(os.Stderr, "%s\t%s%s\n", dbgo.ColorGreen, x, dbgo.ColorReset)
		}
	}
}

/* vim: set noai ts=4 sw=4: */
