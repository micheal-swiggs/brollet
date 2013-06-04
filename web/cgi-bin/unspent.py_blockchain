#!/usr/bin/env python


# reads JSON and outputs JSON
# given an arry of addresses return addresses with spendable balance


# See http://blockchain.info/api/blockchain_api "Unspent outputs" for more info

# use blockchain.info to get the info on the given bitcoin addreesses
#   and returns only the information for unspent addresses which is needed
#   to create transactions for spending it.
# returned object has the following structure:
# 
# [
#   {"bitcoinAddress1 n":
#       {"address":'', "sathoshi":__, "scriptHex":__, "transHash":__, "n":__, "block":__},
#    "bitcoinAddress2 n":
#       {"address":'', "sathoshi":__, "scriptHex":__, "transHash":__, "n":__, "block":__},
# ]
#
# If the scriptPubKey is not given the client figures it out from scriptHex
# If the address is not given and the client figures it out from scriptHex
# If the value is not given the client computes it from sathoshi
#

import sys
import os
import urllib2 as url
import json

def endian(s):
  out = ''
  i = len(s)
  while i>0:
    out = out + s[i-2:i]
    i = i - 2
  return out

print "Content-type: text/plain\n"

try:
  conlen = int(os.environ['CONTENT_LENGTH'])
  rawinp = sys.stdin.read(conlen)
except Exception:
  rawinp = sys.stdin.read()

myaddresses = json.loads(rawinp)

print >> sys.stderr, rawinp

#print myaddresses

try:
  if len(myaddresses) < 1: print '{}'; sys.exit()
except Exception:
  print '{0}'; sys.exit()


bex = "http://blockchain.info/unspent?address=";

#ba = "19sPseiqG3fu7bJfD8JmzAEpEB7EFeUpCa"
#ba = "1M6MHpwJ4MsLo6GTGxH2DVets87WKg8L3B"
#myaddresses = [ba]

ba = "&address=".join(myaddresses)
#print ba
try:
  res = url.urlopen(bex+ba)
except Exception:
  print '{}'; sys.exit()
data = res.read()

#print data
#sys.exit()

res = json.loads(data)
uo = res['unspent_outputs']

trans = {}
for r in uo:
  i = r
# for now set blocknumber to confirmations; TODO - figure out block number
  block = i['confirmations']

  i['tx_hash'] = endian(i['tx_hash'])

  tr = i['tx_hash']+' '+str(i['tx_output_n'])
  trans[tr] = {'address': '', 'sathoshi': i['value'], 'scriptHex': i['script'], 'transHash': i['tx_hash'], 'n': i['tx_output_n'], 'block': block}

#sys.exit()

unspent = {}
for t, v in trans.items():
  if v != 'spent':
    unspent[t] = v

print json.dumps(unspent)
#print unspent

