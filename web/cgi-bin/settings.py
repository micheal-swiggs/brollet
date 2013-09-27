#!/usr/bin/env python

# read JSON input
# make sure password matches the one in the password file
# if not exit with error message
# if the selected send program is different than the current one
#   do a file system copy to copy over the file to send.py
# if the selected unspent program is different than the current one
#   do a file system copy to copy over the selected file to unspent.py
# if electurm was selected then check which electrum server is responsive
#        and add it to the electrum config file.
#

import sys
import os
import urllib2 as url
import hashlib
import string
import random
import json
from subprocess import Popen, PIPE, STDOUT
import access

def writeConf(o):
  c = json.dumps(o)
  open('cgi-bin/config.json', 'w').write(c)

def shell(cmd):
  p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
  output = p.stdout.read()
  return output

def randString(size=6, chars=string.ascii_uppercase + string.digits):
  return ''.join(random.choice(chars) for x in range(size))

def currentConfiguration(conf):
  send = conf.get('send', '')
  unspent = conf.get('unspent', '')
  emailSettings = conf.get('email','')
  smtphost = emailSettings.get('host', '')
  smtpport = emailSettings.get('port', '')
  smtpusername = emailSettings.get('username','')
  res = {'status':'OK', 'message':'Current settings:', 'send':send, 'unspent':unspent,
         'smtphost':smtphost, 'smtpport': smtpport, 'smtpusername': smtpusername}
  print json.dumps(res)
  sys.exit()

print "Content-type: text/plain\n"

try:
  conlen = int(os.environ['CONTENT_LENGTH'])
  rawinp = sys.stdin.read(conlen)
except Exception:
  rawinp = sys.stdin.read()

try:
  inp = json.loads(rawinp)
except Exception:
  res = {'status':'Error', 'message':'Input must be in JSON format.'}
  print json.dumps(res)
  sys.exit()


print >> sys.stderr, rawinp

conf = access.readConf()
savedpassword = conf.get('password', 'change')
password = inp.get('password', '')

if access.isDefaultPassword(savedpassword): access.changePassword()
if not access.validPassword(password): access.incorrectPassword()

action = inp.get('action', '')

if (action == 'get'): currentConfiguration(conf)

emailSettings = conf.get('email','')

if (action == 'set'):

  value = inp.get('value', '')
  if value == '':
    res = {'status':'Error', 'message':'No value given.'}
    print json.dumps(res)
    sys.exit()

  sendVal = value['send']
  if not os.path.isfile("cgi-bin/send.py_"+sendVal):
    res = {'status':'Error', 'message':'No file found. '+sendVal}
    print json.dumps(res)
    sys.exit()
  shell("cp cgi-bin/send.py_"+sendVal+" cgi-bin/send.py")
  conf['send'] = sendVal

  emailVal = value['email']
  oldSmtpPassword = emailSettings.get('password','')
  newSmtpPassword = emailVal.get('password','')
  if newSmtpPassword == '':
    emailVal['password'] = oldSmtpPassword
  conf['email'] = emailVal

  unspentVal = value['unspent']
  if not os.path.isfile("cgi-bin/unspent.py_"+unspentVal):
    res = {'status':'Error', 'message':'No file found.'+unspentVal}
    print json.dumps(res)
    sys.exit()
  shell("cp cgi-bin/unspent.py_"+unspentVal+" cgi-bin/unspent.py")
  conf['unspent'] = unspentVal

  writeConf(conf)
  currentConfiguration(conf)

res = {'status':'Error', 'message':'no action'}
print json.dumps(res)
sys.exit()


