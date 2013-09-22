#!/usr/bin/env python
import json
import sys

def readConf():
    c = open('cgi-bin/config.json', 'r').read()
    o = json.loads(c)
    return o

def incorrectPassword():
    res = {'status':'Error', 'message':'Incorrect password.'}
    print json.dumps(res)
    sys.exit()

def validPassword(sentPassword):
    conf = readConf()
    storedPassword = conf.get('password', 'change')
    if sentPassword == 'change' or sentPassword != storedPassword: return False
    return True

