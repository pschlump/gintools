#!/Users/philip/anaconda3/bin/python

import sys
import inspect
import json
from db.db import debug_print 
from colors.colors import red, green, yellow, magenta, cyan, white, reset

def connecToRedis( host, port, auth, database ) :
    print ( f"host={host} port={port} quth={quth} databsase={databsase}" )

def openLogConnection ( ) :
    print ( "xyzzy" )

def sendLogConnection ( ) :
    print ( "xyzzy" )

def closeLogConnection ( ) :
    print ( "xyzzy" )



#
# Testing
#
# From the command line you can run this with options that test all of the code.
# (also you can use this to send messages to the logger from the command line)
#
# python logger_lib.py 
#       --host [hostIP|domain-name] --port [port-number:6] --auth [redis-password] --database N 
#       --auth-key [key]
#       --req-id R 
#       --file-name F
#       --cluser-name C
#       --msg "message"
#       --cfg "./cfg.json"      JSON config file for things like --host,--port,--auth,--database,--auth-key
#
if __name__ == "__main__":

    arg_host = "127.0.0.1"
    arg_port = "6379"
    arg_auth = ""
    arg_database = "0"
    arg_cfg = "./cfg.json"

    cfg_read = False

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
                # xyzzy - read cfg.json file and set values.

    if not cfg_read  :
        print ( f"readin in {arg_cfg}" )

    print ( f"host= {arg_host}" )
    print ( f"port= {arg_port}" )
    print ( f"auth= {arg_auth}" )
    print ( f"database= {arg_database}" )

#    # cmd=0 style=1 data=2 id=3 output=4
#    if len(sys.argv) != 7:
#        print ( f'Invalid arguments, should be 6, got {len(sys.argv)-1}' )
#        exit(1)
#
#    style_name = sys.argv[1]        # Simple-Resume
#    data_json = sys.argv[2]         # Data to read in
#    document_id = sys.argv[3]       #
#    output_fn = sys.argv[4]         #
#    request_id = sys.argv[5]        #
#    template_name = sys.argv[6]     #
#
#    db_print_data = False
