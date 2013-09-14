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

def readConf():
  c = open('cgi-bin/config.json', 'r').read()
  o = json.loads(c)
  return o

def writeConf(o):
  c = json.dumps(o)
  open('cgi-bin/config.json', 'w').write(c)

def shell(cmd):
  p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
  output = p.stdout.read()
  return output

def randString(size=6, chars=string.ascii_uppercase + string.digits):
  return ''.join(random.choice(chars) for x in range(size))


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

#print myaddresses

savedpassword = 'abc'

action = inp.get('action', '')

if (action == 'get'):
  conf = readConf()
#  conf = {"a":"a"}
  send = conf.get('send', '')
  unspent = conf.get('unspent', '')
  password = conf.get('password','change')
  emailSettings = conf.get('email','')
  smtphost = emailSettings.get('host', '')
  smtpport = emailSettings.get('port', '')
  smtpusername = emailSettings.get('username','')
  if (password == 'change'): password = randString(30)
  hash = hashlib.sha256(password).hexdigest()
  res = {'status':'OK', 'message':'Current settings:', 'send':send, 'unspent':unspent,
         'smtphost':smtphost, 'smtpport': smtpport, 'smtpusername': smtpusername}
  print json.dumps(res)
  sys.exit()

# check the password before making changes
conf = readConf()
savedpassword = conf.get('password','change')
password = inp.get('password', '')
send = conf.get('send', '')
unspent = conf.get('unspent', '')
emailSettings = conf.get('email','')
smtphost = emailSettings.get('host', '')
smtpport = emailSettings.get('port', '')
smtpusername = emailSettings.get('username','')

if password != savedpassword or savedpassword == 'change':
  res = {'status':'Error', 'message':'Incorrect password.', 'send':send, 'unspent':unspent,
         'smtphost':smtphost, 'smtpport': smtpport, 'smtpusername': smtpusername}
  print json.dumps(res)
  sys.exit()


if (action == 'set'):
#  res = {'status':'Error', 'message':'No file found. '}
#  print json.dumps(res)
#  sys.exit()

  conf = readConf()
  field = inp.get('field', '')
  value = inp.get('value', '')
  if value == '':
    res = {'status':'Error', 'message':'No value given.'}
    print json.dumps(res)
    sys.exit()
  if field == 'send':
    if not os.path.isfile("cgi-bin/send.py_"+value):
      res = {'status':'Error', 'message':'No file found. '+value}
      print json.dumps(res)
      sys.exit()
    shell("cp cgi-bin/send.py_"+value+" cgi-bin/send.py")
    conf['send'] = value
  if field == 'email':
    oldSmtpPassword = emailSettings.get('password','')
    newSmtpPassword = value.get('password','')
    if newSmtpPassword == '':
      value['password'] = oldSmtpPassword
    conf['email'] = value
  if field == 'unspent':
    if not os.path.isfile("cgi-bin/unspent.py_"+value):
      res = {'status':'Error', 'message':'No file found.'+value}
      print json.dumps(res)
      sys.exit()
    shell("cp cgi-bin/unspent.py_"+value+" cgi-bin/unspent.py")
    conf['unspent'] = value
  writeConf(conf)
  send = conf.get('send', '')
  unspent = conf.get('unspent', '')
  password = conf.get('password','change')
  emailSettings = conf.get('email','')
  smtphost = emailSettings.get('host', '')
  smtpport = emailSettings.get('port', '')
  smtpusername = emailSettings.get('username','')
  if (password == 'change'): password = randString(30)
  hash = hashlib.sha256(password).hexdigest()
  res = {'status':'OK', 'message':'Current settings:', 'send':send, 'unspent':unspent,
         'smtphost':smtphost, 'smtpport': smtpport, 'smtpusername': smtpusername}
  print json.dumps(res)
  sys.exit()


#res = {'status':'OK', 'message':'got it'}
res = {'status':'Error', 'message':'no action'}
print json.dumps(res)
sys.exit()


