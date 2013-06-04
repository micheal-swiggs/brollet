#!/usr/bin/env python

# reads JSON and outputs JSON
# given a transaction, send it to the bitcoin network

# Using blockchain.info/pushtx to send the transaction

import sys
import os
import json
import re
import urllib2

print "Content-type: text/plain\n"


# read the transaction
try:
  conlen = int(os.environ['CONTENT_LENGTH'])
  rawinp = sys.stdin.read(conlen)
except Exception:
  rawinp = sys.stdin.read()

print >> sys.stderr, rawinp


if rawinp == '':
  res = {'status':'Error', 'error':'No input given.'}
  print json.dumps(res)
  sys.exit()  
txs = json.loads(rawinp)

tx = txs.get('tx', '')
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

