package timed_call

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/gintools/metrics"
	"go.uber.org/zap"
)

/*
package timed_call
	-Initialize - /metrics + log
	+Add Function
	+Set Time
	-Stop Call
	-Kick
*/

type TimedCallFunc func(cc *TimedCallType, data interface{}) error

type TimedCallType struct {
	// Configuration data
	gCfg *data.BaseConfigType
	// Debug flags like prevent send of tc for testing
	DbFlag map[string]bool
	// Log file to write logging to
	tcLogFilePtr *os.File

	// Logging and Metrics
	md     *metrics.MetricsData
	logger *zap.Logger

	// Timed Sender Data
	nTicks     int
	ch         chan string
	timeout    chan string
	sleep_time int
	lock       sync.Mutex

	callbackFunctions []TimedCallFunc // Using a "callback" pattern
	Data              []interface{}   // Config per-function (or use a closure)

	// ------------------------------------------------- Config -------------------------------------------------
	// Database Context and Connection
	//
	// Will be used by the LogError, LogSuccess fuctions to track tc.
	conn *pgxpool.Pool
	ctx  context.Context
}

func NewTimedCall(gcfg *data.BaseConfigType, monitor_prefix string, st int, db map[string]bool, f *os.File, conn *pgxpool.Pool, ctx context.Context, lgr *zap.Logger, xmd *metrics.MetricsData) *TimedCallType {

	if xmd != nil {
		validKeys := []metrics.MetricsTypeInfo{
			{
				Key:  monitor_prefix + "_successful_calls",
				Desc: "Count of Successful Emails Sent",
			},
			{
				Key:  monitor_prefix + "_failed_calls",
				Desc: "Count of Failed Emails Sent",
			},
			{
				Key:  monitor_prefix + "_sql_error",
				Desc: "Count of sql errors",
			},
		}

		xmd.AddMetricsKeys(validKeys)
	}

	tc := &TimedCallType{
		gCfg:         gcfg,
		DbFlag:       db,
		tcLogFilePtr: f,
		conn:         conn,
		ctx:          ctx,
		logger:       lgr,
		md:           xmd,
		ch:           make(chan string, 1),
		timeout:      make(chan string, 2),
		sleep_time:   st,
	}

	tc.initializeTimedSender()

	return tc
}

func (tc *TimedCallType) AddFunc(fx TimedCallFunc, dt interface{}) {
	tc.lock.Lock()
	defer tc.lock.Unlock()
	tc.callbackFunctions = append(tc.callbackFunctions, fx)
	tc.Data = append(tc.Data, fx)
}

func (tc *TimedCallType) SetTime(t int) {
	tc.lock.Lock()
	defer tc.lock.Unlock()
	tc.sleep_time = t
}

// xyzzy - TODO - StopCall

// xyzzy - TODO - Kick

func TimedDispatch(tc *TimedCallType) {
	for {
		select {
		case <-tc.ch:
			dbgo.Printf("%(blue)Chanel Activated\n")
			for ii, fx := range tc.callbackFunctions {
				fx(tc, tc.Data[ii])
			}
			// tc.TemplateAndSend()

		case <-tc.timeout:
			ts := time.Now().Format("2006-01-02 15:04:05")
			dbgo.Printf("%(blue)Clock-Ping At %s / Email Fetch Template and Send%(reset)\n", ts)
			for ii, fx := range tc.callbackFunctions {
				fx(tc, tc.Data[ii])
			}
		}
	}
}

// GetCurTics returns the number of times that a timeout has saved the data.
func (tc *TimedCallType) GetCurTick() int {
	return tc.nTicks
}

func (tc *TimedCallType) initializeTimedSender() {

	// ------------------------------------------------------------------------------
	// Setup live monitor (timed insert)
	// ------------------------------------------------------------------------------
	go TimedDispatch(tc)

	// ticker on channel - send once a minute
	go func(n int) {
		for {
			time.Sleep(time.Duration(n) * time.Second)
			tc.timeout <- "timeout"
			tc.nTicks++
		}
	}(tc.sleep_time)
}

/* vim: set noai ts=4 sw=4: */
