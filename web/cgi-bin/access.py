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

def changePassword():
    res = {'status':'Error', 'message':'Currently the default password is set. Change the password to something more secure.'}
    print json.dumps(res)
    sys.exit()

def validPassword(sentPassword):
    conf = readConf()
    storedPassword = conf.get('password', 'change1')
    if isDefaultPassword(sentPassword) or sentPassword != storedPassword: return False
    return True

def isDefaultPassword(sentPassword):
    return sentPassword == 'change1'
