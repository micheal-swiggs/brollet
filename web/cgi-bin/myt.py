#!/usr/bin/env python

# reads JSON and outputs JSON
# given an arry ofaddresses return addresses with spendable balance


# See http://blockexplorer.com/q/mytransactions for more info

# use blockexper.com to get the info on the given bitcoin addreesses
#   and returns only the information for unspent addresses which is needed
#   to create transactions for spending it.

import sys
import urllib2 as url
import json

print "Content-type: text/plain\n"

#ba = "19sPseiqG3fu7bJfD8JmzAEpEB7EFeUpCa"
#ba = "1M6MHpwJ4MsLo6GTGxH2DVets87WKg8L3B"
ba = "1Duz1TzCgfcy9PKpoz7Z9z9LNZ92BunR1e"
myaddresses = [ba]

#rawinp = sys.stdin.read()
#myaddresses = json.loads(rawinp)

#print myaddresses

try:
  if len(myaddresses) < 1: print '{}'; sys.exit()
except Exception:
  print '{0}'; sys.exit()


bex = "http://blockexplorer.com/q/mytransactions/";

ba = ".".join(myaddresses)
try:
  res = url.urlopen(bex+ba)
except Exception:
  print '{}'; sys.exit()
data = res.read()

#print data

res = json.loads(data)

trans = {}
for r in res:
  txh = res[r]['hash']
  if res[r].get('out', ''):  # we have to use the get() method to avoid KeyError exception
    txt = 'out'
    n = 0
    for i in res[r]['out']:
      if i.get('address','') in myaddresses:
        hash = txh
        tr = hash+' '+str(n)
        spent = trans.get(tr, '')
        if spent == '':
          trans[tr] = {'address': i['address'], 'value': i['value'], 'scriptPubKey': i['scriptPubKey'], 'transHash': hash, 'n': n+1}
      n = n + 1
  if res[r].get('in', ''):
    txt = 'in'
    for i in res[r]['in']:
      if i.get('address','') in myaddresses:
        hash = i['prev_out']['hash']
        n = i['prev_out']['n']
        trans[hash+' '+str(n)] = 'spent'

unspent = {}
for t, v in trans.items():
  if v != 'spent':
    unspent[v['address']] = v

print json.dumps(unspent)
#print unspent



