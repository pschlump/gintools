#!/Users/philip/anaconda3/bin/python

#
# From:  https://redis-py.readthedocs.io/en/stable/advanced_features.html
# Description: listens to a changel 'my-c' for messages. Prints them.
#

import sys
import inspect
import json
import redis

from db.db import debug_print 
from colors.colors import red, green, yellow, magenta, cyan, white, reset

db1 = True

r = redis.Redis(host="127.0.0.1", port="6379", decode_responses=True)
r.publish( 'my-c','from python' )
r.publish( 'my-c','from python' )
r.publish( 'my-c','from python' )
r.publish( 'my-c','from python' )

