package metrics

// Copyright (C) Philip Schlump, 2016-2018, 2023.
// MIT Licensed.  See LICENSE.mit file.
// BSD Licensed.  See LICENSE.bsd file.

// Create the storage system, call it "storeStats" -- Connect to Redis, Memory, Disk etc.
// Create the Metrics - pass it "storeStats"

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pschlump/dbgo"
	"github.com/pschlump/gintools/data"
	"github.com/pschlump/scany/pgxscan"
	"github.com/thoas/stats"
)

type MetricsData struct {
	Data              map[string]float64
	prometheusCounter map[string]*prometheus.Desc
	Safe              sync.Mutex
	SaveRateSeconds   int
	SaveKey           string
}

type MetricsTypeInfo struct {
	Key  string
	Desc string
}

var timeout chan string = make(chan string, 2)
var nTicks int = 0
var ch chan string = make(chan string, 1)

var conn *pgxpool.Pool
var ctx context.Context

var gCfg *data.BaseConfigType
var DbFlag map[string]bool = make(map[string]bool)
var logFilePtr *os.File = os.Stderr

// Stats provide response time, status code count, etc.
var Stats *stats.Stats

func NewMetricsData(saveKey string, validKeys []MetricsTypeInfo, saveRateSeconds int, xgCfg *data.BaseConfigType, xdb map[string]bool, xlfp *os.File, xconn *pgxpool.Pool, xctx context.Context) (md *MetricsData) {
	logFilePtr = xlfp
	gCfg = xgCfg
	conn = xconn
	ctx = xctx
	DbFlag = xdb

	md = &MetricsData{
		Data:              make(map[string]float64),
		SaveRateSeconds:   saveRateSeconds,
		SaveKey:           saveKey,
		prometheusCounter: make(map[string]*prometheus.Desc),
	}
	for _, kk := range validKeys {
		md.Data[kk.Key] = 0
		md.prometheusCounter[kk.Key] = prometheus.NewDesc(kk.Key, kk.Desc, nil, nil)
	}

	// ------------------------------------------------------------------------------
	// create periodic timed data save.  If "memory" then no save
	// ------------------------------------------------------------------------------
	go timedDispatch(md)

	// ticker on channel - send once a minute
	go func(n int) {
		for {
			time.Sleep(time.Duration(n) * time.Second)
			timeout <- "timeout"
			nTicks++
		}
	}(saveRateSeconds)

	Stats = stats.New()

	md.GetData()
	return
}

func SetupRoutes(router *gin.Engine) {

	router.GET("/metrics", func(c *gin.Context) {
		promhttp.Handler().ServeHTTP(c.Writer, c.Request)
	})

	router.GET("/stats", func(c *gin.Context) {
		c.JSON(http.StatusOK, Stats.Data())
	})

}

// StatMiddleware response time, status code count, etc.
func StatMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		beginning, recorder := Stats.Begin(c.Writer)
		c.Next()
		Stats.End(beginning, stats.WithRecorder(recorder))
	}
}

/*
CREATE TABLE if not exists t_key_value (
	id			uuid DEFAULT uuid_generate_v4() not null primary key,
	key			text not null,	-- the key.
	data		jsonb,			-- the data.
	updated 	timestamp, 									 						-- Project update timestamp (YYYYMMDDHHMMSS timestamp).
	created 	timestamp default current_timestamp not null 						-- Project creation timestamp (YYYYMMDDHHMMSS timestamp).
);
*/

func (md *MetricsData) GetData() {
	if md == nil {
		return
	}
	stmt := `select data::text as "x" from t_key_value where key = $1`
	dt, err := SqlRunStmt(stmt, md.SaveKey)
	if err != nil {
		fmt.Fprintf(logFilePtr, "Error on stmt ->%s<- data ->%s<- Select: %s\n", stmt, XData(md.SaveKey), err)
		return
	}
	fmt.Fprintf(logFilePtr, "Success on stmt ->%s<- data ->%s<- results %s\n", stmt, XData(md.SaveKey), dbgo.SVarI(dt))
	if len(dt) == 0 {
		return
	}
	if len(dt) != 1 {
		fmt.Fprintf(logFilePtr, "Invalid length for data: %d, should be 1\n", len(dt))
		return
	}
	err = json.Unmarshal([]byte(dt[0]["x"].(string)), &md.Data)
	if err != nil {
		fmt.Fprintf(logFilePtr, "Unmarshal error: %s data ->%s<-\n", err, dt[0]["x"])
		return
	}
}

func (md *MetricsData) SaveData() {
	if md == nil {
		return
	}
	stmt := `
		INSERT INTO t_key_value ( key, data ) 
			VALUES ( $1, $2::jsonb )
			On CONFLICT on CONSTRAINT t_key_value_uniq1
			DO
			   UPDATE SET data = $2::jsonb
	`
	// On CONFLICT(key) DO NOTHING
	_, err := SqlRunStmt(stmt, md.SaveKey, dbgo.SVar(md.Data))
	if err != nil {
		fmt.Fprintf(logFilePtr, "Invalid insert ->%s<- data:%s error:%s\n", stmt, XData(md.SaveKey, dbgo.SVar(md.Data)), err)
		return
	}
}

// timedDispatch waits for a "kick" or a timeout and calls QrGenerate forever.
func timedDispatch(md *MetricsData) {
	for {
		select {
		case <-ch:
			ts := time.Now().Format("2006-01-02 15:04:05")
			if DbFlag["monitor-timed-data-save"] {
				dbgo.Printf("%(magenta)Chanel Activated via Message %s / Prometheus Metrics Data Save - %(yellow)%(LF)%(reset)\n", ts)
			}
			md.SaveData()

		case <-timeout:
			ts := time.Now().Format("2006-01-02 15:04:05")
			if DbFlag["monitor-timed-data-save"] {
				dbgo.Printf("%(magenta)Clock-Ping At %s / Prometheus Metrics Data Save - %(yellow)%(LF)%(reset)\n", ts)
			}
			md.SaveData()
		}
	}
}

// GetCurTics returns the number of times that a timeout has saved the data.
func GetCurTick() int {
	return nTicks
}

// AddMetricsKeys add additional keys later in processing
func (md *MetricsData) AddMetricsKeys(validKeys []MetricsTypeInfo) {
	dbgo.Fprintf(os.Stderr, "%(red)in metrics  !!!!!\n")
	if md == nil {
		dbgo.Fprintf(os.Stderr, "%(red)Just before md is NIL !!!!!\n")
		return
	}
	if md.Data == nil {
		md.Data = make(map[string]float64)
		md.prometheusCounter = make(map[string]*prometheus.Desc)
	}
	for _, kk := range validKeys {
		if _, ok := md.Data[kk.Key]; !ok {
			md.Data[kk.Key] = 0
			md.prometheusCounter[kk.Key] = prometheus.NewDesc(kk.Key, kk.Desc, nil, nil)
		}
	}
}

func (md *MetricsData) AddCounter(CounterName string, count int) (err error) {
	if md == nil {
		return
	}
	md.Safe.Lock()
	defer md.Safe.Unlock()

	vv, ok := md.Data[CounterName]
	if !ok {
		fmt.Fprintf(logFilePtr, "Missing / Invalid Counter ->%s<-\n", CounterName)
		return fmt.Errorf("Missing / Invalid Counter ->%s<-", CounterName)
	}
	vv += float64(count)
	md.Data[CounterName] = vv
	return
}

func (md *MetricsData) AddFloatCounter(CounterName string, count float64) (err error) {
	if md == nil {
		return
	}
	md.Safe.Lock()
	defer md.Safe.Unlock()

	vv, ok := md.Data[CounterName]
	if !ok {
		fmt.Fprintf(logFilePtr, "Missing / Invalid Counter ->%s<-\n", CounterName)
		return fmt.Errorf("Missing / Invalid Counter ->%s<-", CounterName)
	}
	vv += count
	md.Data[CounterName] = vv
	return
}

func (md *MetricsData) SetFloatCounter(CounterName string, count float64) (err error) {
	if md == nil {
		return
	}
	md.Safe.Lock()
	defer md.Safe.Unlock()

	vv, ok := md.Data[CounterName]
	if !ok {
		fmt.Fprintf(logFilePtr, "Missing / Invalid Counter ->%s<-\n", CounterName)
		return fmt.Errorf("Missing / Invalid Counter ->%s<-", CounterName)
	}
	vv = count
	md.Data[CounterName] = vv
	return
}

func (md *MetricsData) GetCounter(CounterName string) (rv float64) {
	if md == nil {
		return
	}
	md.Safe.Lock()
	defer md.Safe.Unlock()

	vv, ok := md.Data[CounterName]
	if !ok {
		fmt.Fprintf(logFilePtr, "Missing / Invalid Counter ->%s<-\n", CounterName)
		return 0
	}
	return vv
}

// TODO : Start-Time, End-Time (Duration)

func (md *MetricsData) Close() error {
	if md == nil {
		return nil
	}
	md.SaveData()
	return nil
}

// Convert all of the data to JSON format and return as a string.  This is for periodic saves
func (md *MetricsData) GetDataJson() (rv string) {
	if md == nil {
		return
	}
	md.Safe.Lock()
	defer md.Safe.Unlock()

	return dbgo.SVarI(md.Data)
}

// ResetCounters starts all counters back at 0
func (md *MetricsData) ResetCounters() {
	if md == nil {
		return
	}
	md.Safe.Lock()
	defer md.Safe.Unlock()
	for k := range md.Data {
		md.Data[k] = 0
	}
}

// TODO : Start-Time, End-Time (Duration)

// Describe returns all possible prometheus.Desc
func (md *MetricsData) Describe(ch chan<- *prometheus.Desc) {
	if md == nil {
		return
	}
	for _, vv := range md.prometheusCounter {
		ch <- vv
	}
}

// Collect returns the metrics with values
func (md *MetricsData) Collect(ch chan<- prometheus.Metric) {
	if md == nil {
		return
	}
	for keyName, vv := range md.prometheusCounter {
		// ch <- prometheus.MustNewConstMetric(c.TotalRequestsCount, prometheus.CounterValue, float64(status.StatStorage.GetTotalCount()))
		ch <- prometheus.MustNewConstMetric(vv, prometheus.CounterValue, float64(md.Data[keyName]))
	}
}

// SqlRunStmt will run a single statemt and return the data as an array of maps
func SqlRunStmt(stmt string, data ...interface{}) (rv []map[string]interface{}, err error) {
	if conn == nil {
		dbgo.Fprintf(logFilePtr, "Connection is nil -- no database connected -- :%(LF)\n")
		return
	}
	if DbFlag["monitor-dump-statments"] {
		fmt.Fprintf(os.Stderr, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))
		fmt.Fprintf(logFilePtr, "Database Stmt ->%s<- data ->%s<-\n", stmt, dbgo.SVar(data))
	}

	err = pgxscan.Select(ctx, conn, &rv, stmt, data...)
	if err != nil {
		fmt.Fprintf(logFilePtr, "Sql error: %s stmt: ->%s<- params: %s", err, stmt, XData(data))
		return nil, fmt.Errorf("Sql error: %s stmt: ->%s<- params: %s", err, stmt, XData(data))
	}

	return
}

// XData convers a list of parameters to a JSON data showing what the list contains.  This is returned as a string.
func XData(x ...interface{}) (rv string) {
	rv = dbgo.SVar(x)
	return
}

/*

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pschlump/fmcsa-svr/status"
)


func appStatusHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		result := status.App{}

		result.Version = GetVersion()
		result.TotalCount = status.StatStorage.GetTotalCount()

		c.JSON(http.StatusOK, result)
	}
}
*/

func ResetLogFile(newFp *os.File) {
	logFilePtr = newFp
}

/* vim: set noai ts=4 sw=4: */
