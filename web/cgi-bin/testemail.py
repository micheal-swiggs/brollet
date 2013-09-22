#!/usr/bin/env python
import sys
import os
import json
import traceback
import logging
import simpleemail
import access

print "Content-type: text/plain\n"

logging.basicConfig(filename='../logs/testemail.log', level=logging.DEBUG)
try:
    conlen = int(os.environ['CONTENT_LENGTH'])
    rawinp = sys.stdin.read(conlen)
except Exception:
    rawinp = sys.stdin.read()
print >> sys.stderr, rawinp

if rawinp == '':
    res = {'status':'Error', 'error': 'No input given.'}
    print json.dumps (res)
    sys.exit()
data = json.loads(rawinp)
logging.info(data);

password = data['password']
if not access.validPassword(password): access.incorrectPassword()

emailConfig = data['emailConfig']
emailMsg = data['emailMsg']

try:
    simpleemail.sendemail(emailConfig, emailMsg)
except Exception, err:
    p_err = str(traceback.format_exc())
    print json.dumps({'status': 'Error', 'error': 'Email was not sent.', 'pythonerror': p_err})
    sys.exit(0)

print json.dumps({'status':'OK', 'message': 'Email sent.'})


