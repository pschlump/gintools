package tf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/pschlump/HashStrings"
	"github.com/pschlump/dbgo"
	"github.com/redis/go-redis/v9"
)

type TfType struct {
	Ctx         context.Context
	Rdb         *redis.Client
	ClusterName string
}

func NewSetupTf(ctx context.Context, rdb *redis.Client, ClusterName string) (ex *TfType) {
	return &TfType{
		Ctx:         ctx,
		Rdb:         rdb,
		ClusterName: ClusterName,
	}
}

// CheckRedisWorking does a test set and get to redis client
// rdb is setup as global in main.go
// this is called in main.go if UseRedis == "yes" in local cfg
func (ttf *TfType) CheckRedisWorking() (err error) {
	testkey := "wir_setup:testkey:" + strconv.FormatInt(time.Now().Unix(), 10)
	testval := "test content for redis setup"

	err = ttf.Rdb.Set(ttf.Ctx, testkey, testval, 900*time.Second).Err()
	if err != nil {
		return err
	}

	val, err := ttf.Rdb.Get(ttf.Ctx, testkey).Result()
	if err != nil {
		return err
	}

	if val != testval {
		val_err := errors.New("Value in redis is incorrect. Check key: " + testkey + "\n")
		return val_err
	}

	return
}

func ValidateAuthKeyHmac(AuthKey, Pw string) bool {

	if Pw == "" { // not set, not being used
		return true
	}
	// Pw := gCfg.TestSendEmailPassword // pw := os.Getenv("TEST_SEND_EMAIL_PASSWORD")

	// To Generate the HMAC auth key, See: ../gen-email-key or $tools/tools/gen-email-key
	if HashStrings.HashStrings(Pw+AuthKey) != "2572640f43d8b184d14c2b7f0d255a752fd4c3d674dba969046d5c611d47b8d5" {

		dbgo.Fprintf(os.Stderr, "%(red)Requires AuthKey to be valid %(LF), %s --\nSee ~/.secret/setup.sh or run generation tool ../gen-email-key/gen-email-key.go\n    ->%s<-\n    Desired HMAC is: ->%s<-\n", dbgo.LF(-2), AuthKey, "2572640f43d8b184d14c2b7f0d255a752fd4c3d674dba969046d5c611d47b8d5")
		return false
	}

	if db8 {
		dbgo.Fprintf(os.Stderr, "%(green)Have valid AuthKey value (should have been authenticated also) %(LF)\n")
	}
	return true
}

var PubSubLogKey = "log:pub-sub-channel:"
var PubSubLogIAmAliveKey = "log:-i-am-alive-"
var PubSubLogIAmAliveValue = "yes"

type LogMessage struct {
	Cmd         string `json:"Cmd,omitempty"`
	Data        string `json:"Data,omitempty"`
	ReqId       string `json:"ReqId,omitempty"`
	FileName    string `json:"FileName,omitempty"`
	ClusterName string `json:"ClusterName,omitempty"`
	AuthKey     string `json:"AuthKey,omitempty"`
}

type RedisLogger struct {
	rdb         *redis.Client
	ctx         context.Context
	ReqId       string
	FileName    string
	ClusterName string
	AuthKey     string `json:"AuthKey,omitempty"`
}

func (ttf *TfType) NewRedisLogger(ReqId, AuthKey, clusterName string) (lm *RedisLogger, wp io.WriteCloser, err error) {
	if db44 {
		dbgo.Fprintf(os.Stderr, "%(greenw)NewRedisLogger%(magenta) clusterName=%s %(yellow)At:%(LF)\n", ttf.ClusterName)
	}
	if err := ttf.Rdb.Publish(ttf.Ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "open", ReqId: ReqId, ClusterName: clusterName, AuthKey: AuthKey})).Err(); err != nil {
		fmt.Printf("Failed to publish, open, to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
	}
	x := &RedisLogger{
		rdb:         ttf.Rdb,
		ctx:         ttf.Ctx,
		ReqId:       ReqId,
		ClusterName: clusterName,
		AuthKey:     AuthKey,
	}
	return x, x, nil
}
func (ttf *TfType) NewRedisLoggerFile(FileName, AuthKey, clusterName string) (lm *RedisLogger, wp io.WriteCloser, err error) {
	if db44 {
		dbgo.Fprintf(os.Stderr, "%(greenw)NewRedisLogger%(magenta) clusterName=%s %(yellow)At:%(LF)\n", clusterName)
	}
	if err := ttf.Rdb.Publish(ttf.Ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "open", FileName: FileName, ClusterName: clusterName, AuthKey: AuthKey})).Err(); err != nil {
		fmt.Printf("Failed to publish, open/file, to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
	}
	x := &RedisLogger{
		rdb:         ttf.Rdb,
		ctx:         ttf.Ctx,
		FileName:    FileName,
		ClusterName: clusterName,
		AuthKey:     AuthKey,
	}
	return x, x, nil
}

func (ee RedisLogger) Write(p []byte) (int, error) {
	// fmt.Printf("Write >%s<, ReqId >%s<-\n", p, ee.ReqId)
	if ee.rdb == nil {
		fmt.Fprintf(os.Stderr, "%s\n", p)
		return len(p), nil
	}
	if err := ee.rdb.Publish(ee.ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "data", Data: string(p), ReqId: ee.ReqId, FileName: ee.FileName, ClusterName: ee.ClusterName, AuthKey: ee.AuthKey})).Err(); err != nil {
		fmt.Printf("Failed to publish to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
		return 0, err
	}
	return len(p), nil
}

func (ee RedisLogger) Close() (err error) {
	if err = ee.rdb.Publish(ee.ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "close", ReqId: ee.ReqId, FileName: ee.FileName, ClusterName: ee.ClusterName, AuthKey: ee.AuthKey})).Err(); err != nil {
		fmt.Printf("Failed to publish, close, to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
	}
	return
}

func (ee RedisLogger) Flush() (err error) {
	if err = ee.rdb.Publish(ee.ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "flush", ReqId: ee.ReqId, AuthKey: ee.AuthKey})).Err(); err != nil {
		fmt.Printf("Failed to publish, flush, to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
	}
	return err
}

func (ee RedisLogger) Command(cmd string) (err error) {
	if err = ee.rdb.Publish(ee.ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: cmd, ReqId: ee.ReqId, AuthKey: ee.AuthKey})).Err(); err != nil {
		fmt.Printf("Failed to publish, %s, to the log pubsub channel, %s: error:%s\n", cmd, PubSubLogKey, err)
	}
	return
}

const db8 = false
const db44 = false

/* vim: set noai ts=4 sw=4: */
