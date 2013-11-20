#!/usr/bin/env python

# reads JSON and outputs JSON
# given a transaction, send it to the bitcoin network

# Using blockchain.info/pushtx to send the transaction

import cgi
import sys
import os
import json
import re
import urllib2
import logging

logging.basicConfig(filename='../logs/debug.log', level=logging.DEBUG)

print "Content-type: text/plain\n"

fStorage = cgi.FieldStorage()
try:
    len(fStorage)
except Exception, err:
    print json.dumps({'status':'Error', 'error': 'No parameters specified.'})
    sys.exit()

if "tx" not in fStorage:
    res = {'status': 'Error', 'error':'Transaction not specified'}
    print json.dumps(res)
    sys.exit()
tx = fStorage["tx"].value

if tx == '' :
  res = {'status':'Error', 'error':'No transaction given.'}
  print json.dumps(res)
  sys.exit()

if len(tx) < 50:
  res = {'status':'Error', 'error':'Transaction too short.'}
  print json.dumps(res)
  sys.exit()


url = "http://blockchain.info/pushtx"
data = "tx="+tx
req = urllib2.Request(url, data)
response = urllib2.urlopen(req)
output = response.read()


if re.search(r'error', output, re.I):
  res = {'status':'Error', 'error':output}
else:
#print output
  res = {'status':'OK', 'message':output}
print json.dumps(res)

