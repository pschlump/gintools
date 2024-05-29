package tf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/pschlump/dbgo"
	"github.com/redis/go-redis/v9"
)

// CheckRedisWorking does a test set and get to redis client
// rdb is setup as global in main.go
// this is called in main.go if UseRedis == "yes" in local cfg
func CheckRedisWorking() (err error) {
	testkey := "wir_setup:testkey:" + strconv.FormatInt(time.Now().Unix(), 10)
	testval := "test content for redis setup"

	err = rdb.Set(ctx, testkey, testval, 900*time.Second).Err()
	if err != nil {
		return err
	}

	val, err := rdb.Get(ctx, testkey).Result()
	if err != nil {
		return err
	}

	if val != testval {
		val_err := errors.New("Value in redis is incorrect. Check key: " + testkey + "\n")
		return val_err
	}

	return
}

var PubSubLogKey = "log:pub-sub-channel:"
var PubSubLogIAmAliveKey = "log:-i-am-live-"
var PubSubLogIAmAliveValue = "yes"

type LogMessage struct {
	Cmd        string `json:"Cmd,omitempty"`
	Data       string `json:"Data,omitempty"`
	ReqId      string `json:"ReqId,omitempty"`
	FileName   string `json:"FileName,omitempty"`
	ServerName string `json:"ServerName,omitempty"`
}

type RedisLogger struct {
	rdb        *redis.Client
	ctx        context.Context
	ReqId      string
	FileName   string
	ServerName string
}

func NewRedisLogger(ReqId string, rdb *redis.Client, ctx context.Context) (lm *RedisLogger, wp io.WriteCloser, err error) {
	if err := rdb.Publish(ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "open", ReqId: ReqId})).Err(); err != nil {
		fmt.Printf("Failed to publish, open, to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
	}
	x := &RedisLogger{
		rdb:        rdb,
		ctx:        ctx,
		ReqId:      ReqId,
		ServerName: serverName,
	}
	return x, x, nil
}
func NewRedisLoggerFile(FileName string, rdb *redis.Client, ctx context.Context) (lm *RedisLogger, wp io.WriteCloser, err error) {
	if err := rdb.Publish(ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "open", FileName: FileName})).Err(); err != nil {
		fmt.Printf("Failed to publish, open/file, to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
	}
	x := &RedisLogger{
		rdb:        rdb,
		ctx:        ctx,
		FileName:   FileName,
		ServerName: serverName,
	}
	return x, x, nil
}

func (ee RedisLogger) Write(p []byte) (int, error) {
	fmt.Printf("Write >%s<, ReqId >%s<-\n", p, ee.ReqId)
	if err := rdb.Publish(ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "data", Data: string(p), ReqId: ee.ReqId, FileName: ee.FileName})).Err(); err != nil {
		fmt.Printf("Failed to publish to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
		return 0, err
	}
	return len(p), nil
}

func (ee RedisLogger) Close() (err error) {
	if err = rdb.Publish(ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "close", ReqId: ee.ReqId, FileName: ee.FileName})).Err(); err != nil {
		fmt.Printf("Failed to publish, close, to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
	}
	return
}

func (ee RedisLogger) Flush() (err error) {
	if err = rdb.Publish(ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: "flush", ReqId: ee.ReqId})).Err(); err != nil {
		fmt.Printf("Failed to publish, flush, to the log pubsub channel, %s: error:%s\n", PubSubLogKey, err)
	}
	return err
}

func (ee RedisLogger) Command(cmd string) (err error) {
	if err = rdb.Publish(ctx, PubSubLogKey, dbgo.SVar(LogMessage{Cmd: cmd, ReqId: ee.ReqId})).Err(); err != nil {
		fmt.Printf("Failed to publish, %s, to the log pubsub channel, %s: error:%s\n", cmd, PubSubLogKey, err)
	}
	return
}

/* vim: set noai ts=4 sw=4: */
