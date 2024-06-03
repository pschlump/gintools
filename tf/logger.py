#!/Users/philip/anaconda3/bin/python

import sys
import os
import inspect
import json
import redis

from db.db import debug_print 
from colors.colors import red, green, yellow, magenta, cyan, white, reset

db1 = True

class RedisLogger:

    def __init__( self ):
        self.ClusterName = ""
        self.AuthKey = os.environ["LOGGER_AUTH_KEY"]
        self.Key = "log:pub-sub-channel:"
        self.Conn = null

    def ConnectToRedis ( self, host, port, auth, database ):
        global db1
        if db1:
            print ( f"host={host} port={port} auth={auth} databsase={database}, just before connect" )
        if auth != "":
            self.Conn = redis.Redis(host=host, port=port, decode_responses=True, password=auth)
        else:
            self.Conn = redis.Redis(host=host, port=port, decode_responses=True)

    def OpenLogConnection ( self, cluster_name ):

        self.ClusterName = cluster_name

        record = {
            'Cmd': 'open',
            'ClusterName': self.ClusterName,
            'AuthKey': self.AuthKey,
            'Key': self.Key
        }

        data = json.dumps(record).encode("utf-8")
        self.Conn.publish(self.Key, data)

    def sendLogConnection ( self, msg, req_id, file_name ) :

        if msg == "":
            return

        record = {
            'Cmd': 'data',
            'Data': msg,
            'AuthKey': self.AuthKey
        }
        if req_id != "":
            record['ReqId'] = req_id
        if file_name != "":
            record['FileName'] = file_name
        if self.ClusterName != "":
            record['ClusterName'] = self.ClusterName

        data = json.dumps(record).encode("utf-8")
        self.Conn.publish(self.Key, data)

    def closeLogConnection ( r, cluster_name, auth_key ) :

        record = {
            'Cmd': 'close',
            'ClusterName': self.ClusterName,
            'AuthKey': self.AuthKey
        }

        data = json.dumps(record).encode("utf-8")
        self.Conn.publish(self.Key, data)


    









# r = redis.Redis(host="127.0.0.1", port="6379", decode_responses=True)
# r.publish( 'my-c','from python' )

def connecToRedis( xhost, xport, auth, xdatabase ) :
    global db1
    if db1:
        print ( f"host={xhost} port={xport} auth={auth} databsase={xdatabase}, just before connect" )
    if auth != "":
        r = redis.Redis(host=xhost, port=xport, decode_responses=True, password=auth)
    else:
        r = redis.Redis(host=xhost, port=xport, decode_responses=True)
    rv = {
       'Conn': r,
       'Key':  "log:pub-sub-channel:",
    }
    return rv

def openLogConnection ( conn, cluster_name, auth_key ) :

    """
    type LogMessage struct {
        Cmd         string `json:"Cmd,omitempty"`
        Data        string `json:"Data,omitempty"`
        ReqId       string `json:"ReqId,omitempty"`
        FileName    string `json:"FileName,omitempty"`
        ClusterName string `json:"ClusterName,omitempty"`
        AuthKey     string `json:"AuthKey,omitempty"`
    }
    """

    topic_path = "log:pub-sub-channel:"

    record = {
        'Cmd': 'open',
        'ClusterName': cluster_name,
        'AuthKey': auth_key,
        'Key': topic_path
    }

    data = json.dumps(record).encode("utf-8")
    topic_path = conn['Key']
    r = conn['Conn']
    r.publish(topic_path, data)


def sendLogConnection ( r, msg, req_id, file_name, cluster_name, auth_key ) :

    if msg == "":
        return

    record = {
        'Cmd': 'data',
        'Data': msg,
        'AuthKey': auth_key
    }
    if req_id != "":
        record['ReqId'] = req_id
    if file_name != "":
        record['FileName'] = file_name
    if cluster_name != "":
        record['ClusterName'] = cluster_name

    data = json.dumps(record).encode("utf-8")
    topic_path = conn['Key']
    r = conn['Conn']
    r.publish(topic_path, data)


def closeLogConnection ( r, cluster_name, auth_key ) :

    record = {
        'Cmd': 'close',
        'ClusterName': cluster_name,
        'AuthKey': auth_key
    }

    data = json.dumps(record).encode("utf-8")
    topic_path = conn['Key']
    r = conn['Conn']
    r.publish(topic_path, data)






def readCfg( data_json ):
    db_print_data = False

    try:
        f = open(data_json)
        data = json.load(f)
        print('Loaded data')
        if db_print_data:
            print(json.dumps(data, indent=4)) 
        return data
    except FileNotFoundError:
        print(f'Unable to read:{data_json}, file not found')
    except:
        print(f'Unable to read:{data_json}')

    return 



# ------------------------------------------------------------------------------------------------------
#
# Testing
#
# From the command line you can run this with options that test all of the code.
# (also you can use this to send messages to the logger from the command line)
#
# python logger_lib.py 
#       --cfg "./cfg.json"      JSON config file for things like --host,--port,--auth,--database,--auth-key
#       --host [hostIP|domain-name] --port [port-number:6] --auth [redis-password] --database N 
#       --auth-key [key]
#       --req-id R 
#       --file-name F
#       --cluser-name C
#       --msg "message"
#
if __name__ == "__main__":

    arg_host = "127.0.0.1"
    arg_port = "6379"
    arg_auth = ""
    arg_database = "0"
    arg_cfg = "./cfg.json"

    cfg_read = False

    arg_auth_key = ""
    arg_req_id = ""
    arg_file_name = ""
    arg_cluster_name = ""
    arg_msg = ""

	# RedisConnectPort string `json:"redis_port" default:"6379"`
    if len(sys.argv) > 1:
        for ii in range(len(sys.argv[1:])):
            vv = sys.argv[ii+1]
            print ( f"ii={ii+1} vv={vv}" )
            if vv == "--host" and ii+2 < len(sys.argv):
                arg_host = sys.argv[ii+2]
            elif vv == "--port" and ii+2 < len(sys.argv):
                arg_port = sys.argv[ii+2]
            elif vv == "--auth" and ii+2 < len(sys.argv):
                arg_auth = sys.argv[ii+2]
            elif vv == "--database" and ii+2 < len(sys.argv):
                arg_database = sys.argv[ii+2]
            elif vv == "--cfg" and ii+2 < len(sys.argv):
                arg_cfg = sys.argv[ii+2]
                cfg_read = True
                # read cfg.json file and set values.
                gCfg = readCfg( arg_cfg )
                if "RedisHost" in gCfg:
                    arg_host = gCfg["RedisHost"]
                if "RedisPort" in gCfg:
                    arg_host = gCfg["RedisPort"]
                if "RedisAuth" in gCfg:
                    arg_host = gCfg["RedisAuth"]
                if "RedisDatabase" in gCfg:
                    arg_host = gCfg["RedisDatabase"]

            elif vv == "--auth-key" and ii+2 < len(sys.argv):
                arg_auth_key = sys.argv[ii+2]
            elif vv == "--req-id" and ii+2 < len(sys.argv):
                arg_req_id = sys.argv[ii+2]
            elif vv == "--cluster-name" and ii+2 < len(sys.argv):
                arg_cluster_name = sys.argv[ii+2]
            elif vv == "--file-name" and ii+2 < len(sys.argv):
                arg_file_name = sys.argv[ii+2]
            elif vv == "--msg" and ii+2 < len(sys.argv):
                arg_msg = sys.argv[ii+2]

    """{
        , "RedisDatabase": 0
        , "ClusterName": "victoria.local:redis-log"
        , "LoggerAuthPassword": "$ENV$LOGGER_AUTH_PW"
        , "UseRedis": "yes"
        , "RedisAuthEnabled": "no"
        , "RedisHost": "$ENV$REDIS_HOST"
        , "RedisPort": "$ENV$REDIS_PORT"
        , "RedisAuth": "$ENV$REDIS_AUTH"
        , "UseRedisForLog": "no"
    }"""

    if not cfg_read  :
        # read cfg.json file and set values.
        print ( f"readin in {arg_cfg}" )
        gCfg = readCfg( arg_cfg )
        if "RedisHost" in gCfg:
            arg_host = gCfg["RedisHost"]
        if "RedisPort" in gCfg:
            arg_host = gCfg["RedisPort"]
        if "RedisAuth" in gCfg:
            arg_host = gCfg["RedisAuth"]
        if "RedisDatabase" in gCfg:
            arg_host = gCfg["RedisDatabase"]


    if arg_host == "" or arg_host == 0:
        arg_host = "127.0.0.1"
    if arg_port == "":
        arg_port = "6379"
    if arg_auth_key == "":
        arg_auth_key = os.environ["LOGGER_AUTH_KEY"]

    print ( f"host= {arg_host}" )
    print ( f"port= {arg_port}" )
    print ( f"auth= {arg_auth}" )
    print ( f"database= {arg_database}" )

    conn = connecToRedis( arg_host, arg_port, arg_auth, arg_database ) 
    print ( f"{green}Successfully connected to Redis{reset}" )


    if arg_msg != "":
        if arg_req_id == "" and arg_file_name == "":
            print ( "Must supply one of --req-id UUID or --file-name FN when sending a message" )
            exit(1)

        #debug_print ( f"{green}Yep early exit for testing" )
        #exit(0)

        # def openLogConnection ( conn, cluster_name, auth_key ) :
        openLogConnection ( conn, arg_cluster_name, arg_auth_key ) 
        print ( f"{green}opened logger cluster={arg_cluster_name} auth_key={arg_auth_key}{reset}" )
        # def sendLogConnection ( r, msg, req_id, file_name, cluster_name, auth_key ) :
        sendLogConnection ( conn, arg_msg + "\n", arg_req_id, arg_file_name, arg_cluster_name, arg_auth_key )
        print ( f"{green}message sent to logger{reset}" )
        # def closeLogConnection ( r, cluster_name, auth_key ) :
        closeLogConnection ( conn, arg_cluster_name, arg_auth_key ) 
        print ( f"{green}close logger{reset}" )

    else :
        print ( "Did not do anything, try --msg option" )
        exit(1)


