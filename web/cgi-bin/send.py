#!/usr/bin/env python

# reads JSON and outputs JSON
# given a transaction, send it to the bitcoin network

# Using electrum to send the transaction

import cgi
import sys
import os
import json
import re
from subprocess import Popen, PIPE, STDOUT

def readConf():
  c = open('cgi-bin/config.json', 'r').read()
  o = json.loads(c)
  return o


print "Content-type: application/json;charset=UTF-8\n"

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

# Now send the transaction
os.chdir('cgi-bin/electrum')
pyt = sys.executable
cmd = pyt+' electrum -s electrum.drollette.com:50002:s sendrawtransaction '+tx

#res = {'status':'OK', 'tid':'abc '+cmd}; print json.dumps(res); sys.exit()

p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
output = p.stdout.read()
if re.search(r'error', output, re.I):
  res = {'status':'Error', 'error':output}
else:
#print output
  res = {'status':'OK', 'message':output}
print json.dumps(res)

