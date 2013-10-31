#!/usr/bin/env python
import cgi
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

def sendBitcoinEmail():

    logging.basicConfig(filename='../logs/email.log', level=logging.DEBUG)
    fStorage = cgi.FieldStorage()
    try:
        len(fStorage)
    except Exception, err:
        print json.dumps({'status':'Error', 'error': 'No parameters specified.'})
        sys.exit()

    logging.info(fStorage)
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
    if simpleemail.validport(email_port) != True:
        e_error += simpleemail.validport(email_port)
    if e_error != '':
        print json.dumps ({'status':'Error', 'error': e_error})
        sys.exit()
    emailUsername = emailSettings.get('username','')
    emailPassword = emailSettings.get('password','')

    e_error = ''
    #if emailUsername == '' and emailPassword != '':
    #    e_error = 'SMTP username set, but not SMTP password.'
    #if emailPassword == '' and emailUsername != '':
    #    e_error = 'SMTP username not set, but SMTP password is set.'
    if e_error != '':
        print json.dumps ({'status': 'Error', 'error':e_error})
        sys.exit()

    if "to" not in fStorage:
        res = {'status': 'Error', 'error':'No recipient given.'}
        print json.dumps(res)
        sys.exit()
    to = fStorage["to"].value

    if "sender" not in fStorage:
        res = {'status':'Error', 'error': 'No sender given.'}
        print json.dumps(res)
        sys.exit()
    sender = fStorage['sender'].value

    if "code" not in fStorage:
        res = {'status':'Error', 'error': 'No transaction code given.'}
        print json.dumps(res)
        sys.exit()
    code = fStorage['code'].value

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

try:
    print "Content-type: text/plain\n"
    sendBitcoinEmail()
    print json.dumps({'status':'OK', 'message': 'Email sent.'})
except Exception, err:
    p_err = str(traceback.format_exc())
    print json.dumps({'status':'Error', 'error': 'Email was not sent.', 'pythonerror': p_err})

