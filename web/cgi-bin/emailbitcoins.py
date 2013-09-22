#!/usr/bin/env python
import sys
import os
import json
import traceback
import logging
import simpleemail

def readConf():
    c = open('cgi-bin/config.json', 'r').read()
    o = json.loads(c)
    return o
print "Content-type: text/plain\n"

logging.basicConfig(filename='../logs/email.log', level=logging.DEBUG)
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
logging.info("rawinp")
logging.info(rawinp)
txs = json.loads(rawinp)
logging.info(txs);

conf = readConf()
emailSettings = conf.get('email','')
if emailSettings == '':
    res = {'status':'Error', 'error': 'Email configuration not set.'}
    print json.dumps(res)
    sys.exit()

email_host = emailSettings.get('host','')
email_port = emailSettings.get('port','')
e_error = ''
if email_host == '': e_error = 'SMTP host not set. '
if email_port == '': e_error += 'SMTP port not set.'
if e_error != '':
    print json.dumps ({'status':'Error', 'error': e_error})
    sys.exit()

emailUsername = emailSettings.get('username','')
emailPassword = emailSettings.get('password','')

e_error = ''
if emailUsername == '' and emailPassword != '':
    e_error = 'SMTP username set, but not SMTP password.'
if emailPassword == '' and emailUsername != '':
    e_error = 'SMTP username not set, but SMTP password is set.'
if e_error != '':
    print json.dumps ({'status': 'Error', 'error':e_error})
    sys.exit()


to = txs.get('to','')
if to == '':
    res = {'status': 'Error', 'error':'No recipient given.'}
    print json.dumps(res)
    sys.exit()

sender = txs.get('sender','')
if sender == '':
    res = {'status':'Error', 'error': 'No sender given.'}
    print json.dumps(res)
    sys.exit()

code = txs.get('code', '')
if code == '':
    res = {'status':'Error', 'error': 'No transaction code given.'}
    print json.dumps(res)
    sys.exit()

try:
    email_port = int(email_port)
    emailConfig = {'email_host': email_host, 'email_port': email_port,
                   'email_username': emailUsername, 'email_password': emailPassword}
    emailMsg = { 'sender': sender, 'to': sender,
        'subject': "You send bitcoins from EZWallet",
        'message': "You sent bitcoins to {0}. Use the code below to recover the bitcoins with EZWallet.\n\n{1}\n\n".format(to,code)}
    simpleemail.sendemail(emailConfig, emailMsg)

    emailMsg = { 'to': to, 'sender': sender,
            'subject': "Bitcoins from EZWallet",
            'message': "You received bitcoins from {0}. Use the following code to redeem your bitcoins with EZWallet.\n\n{1}\n\n".format(sender, code)}
    simpleemail.sendemail(emailConfig, emailMsg)
except Exception, err:
    p_err = str(traceback.format_exc())
    print json.dumps({'status':'Error', 'error': 'Email was not sent.', 'pythonerror': p_err})
    sys.exit(0)

print json.dumps({'status':'OK', 'message': 'Email sent.'})
