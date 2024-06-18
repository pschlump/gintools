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
        self.Conn = ""

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

    def SendLogConnection ( self, msg, req_id, file_name ) :

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

    def CloseLogConnection ( self ) :

        record = {
            'Cmd': 'close',
            'ClusterName': self.ClusterName,
            'AuthKey': self.AuthKey
        }

        data = json.dumps(record).encode("utf-8")
        self.Conn.publish(self.Key, data)


    



db_print_data = False
gCfg = {}

def readCfg( cfg_fn, data_dflt ):
    global db_print_data 

    try:
        f = open(cfg_fn)
        data = json.load(f)
        print('Loaded data')
        if db_print_data:
            print(json.dumps(data, indent=4)) 

        for kk in data_dflt:
            if kk not in data :
                data[kk] = data_dflt[kk]

        for kk in data:
            debug_print ( f"2nc loop: kk={kk}, data[kk]={data[kk]}" )
            if isinstance(data[kk], int):
                pass
            elif len(data[kk]) > 5 and data[kk][0:5] == "$ENV$" :
                debug_print ( f"data[{kk}] start siwth $ENV$" )
                if data[kk][5:] in os.environ:
                    debug_print ( f"data[{kk}] is set in environment" )
                    data[kk] = os.environ[data[kk][5:]]
                    debug_print ( f"data[{kk}]={data[kk]}" )

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

    rc = RedisLogger()

    arg_host = ""
    arg_port = ""
    arg_auth = ""
    arg_database = ""
    arg_cfg = "./cfg.json"

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

    data_dflt = {
        "RedisLogHost": "127.0.0.1",
        "RedisLogPort": "6379",
        "RedisLogAuth": "",
        "RedisLogDatabase": "0"
    }

    gCfg = readCfg( arg_cfg, data_dflt )

    if arg_host != "":
        gCfg["RedisLogHost"] = arg_host
    if arg_port != "":
        gCfg["RedisLogPort"] = arg_port
    if arg_auth != "":
        gCfg["RedisLogAuth"] = arg_auth
    if arg_database != "":
        gCfg["RedisLogAuth"] = arg_database
    if arg_cluster_name != "":
        gCfg["ClusterName"] = arg_cluster_name

    print("gCfg after args, init", json.dumps(gCfg, indent=4)) 

    rc.ConnectToRedis ( gCfg["RedisLogHost"], gCfg["RedisLogPort"], gCfg["RedisLogAuth"], gCfg["RedisLogDatabase"] )
    print ( f"{green}Successfully connected to Redis{reset}" )

    if arg_msg != "":
        if arg_req_id == "" and arg_file_name == "":
            print ( "Must supply one of --req-id UUID or --file-name FN when sending a message" )
            exit(1)

        #debug_print ( f"{green}Yep early exit for testing" )
        #exit(0)

        # def OpenLogConnection ( self, cluster_name ):
        rc.OpenLogConnection ( gCfg["ClusterName"] )
        print ( f"{green}opened logger cluster={arg_cluster_name}{reset}" )
        # def SendLogConnection ( self, msg, req_id, file_name ) :
        rc.SendLogConnection ( arg_msg + "\n", arg_req_id, arg_file_name )
        print ( f"{green}message sent to logger{reset}" )
        # def CloseLogConnection ( self ) :
        rc.CloseLogConnection ()
        print ( f"{green}close logger{reset}" )

    else :
        print ( "Did not do anything, try --msg option" )
        exit(1)


