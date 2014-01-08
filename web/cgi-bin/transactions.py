#!/usr/bin/env python

import cgi
import sys
import urllib2 as url
import json
import logging

# Functions from Electrum start
__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58decode(v, length):
    """ decode v into a string of len bytes."""
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]: nPad += 1
        else: break

    result = chr(0)*nPad + result
    if length is not None and len(result) != length:
        return None

    return result

def bc_address_to_hash_160(addr):
    bytes = b58decode(addr, 25)
    return ord(bytes[0]), bytes[1:21]

# Functions from electrum end.

def address_to_script (addr):
    addrtype, hash_160 = bc_address_to_hash_160(addr)
    script = ''
    if addrtype == 0:
        script = '76a9'
        script += '14'
        script += hash_160.encode('hex')
        script += '88ac'
    elif addrtype == 5:
        script = 'a9'
        script += '14'
        script += hash_160.encode('hex')
        script += '87'
    else:
        raise
    return script

def endian(s):
  out = ''
  i = len(s)
  while i>0:
    out = out + s[i-2:i]
    i = i - 2
  return out


logging.basicConfig(filename='../logs/debug.log', level=logging.DEBUG)


print "Content-type: application/json;charset=UTF-8\n"

fStorage = cgi.FieldStorage()
try:
    len(fStorage)
except Exception, err:
    print json.dumps({'status':'Error', 'error': 'No parameters specified.'})
    sys.exit()

if "addresses" not in fStorage:
    res = {'status': 'Error', 'error':'No addresses specified'}
    print json.dumps(res)
    sys.exit()

addresses = fStorage["addresses"].value

try:
    if len(addresses) < 1: print '{}'; sys.exit()
except Exception:
    print '{0}'; sys.exit()


bchain = "http://blockchain.info/multiaddr?cors=true&active="+addresses

try:
    res = url.urlopen(bchain)
except Exception:
    print '{}'; sys.exit()
print res.read()

