#!/usr/bin/env python
import cgi
import sys
import os
import urlparse
import json
import traceback
import logging
import simpleemail


def readConf():
    c = open('cgi-bin/config.json', 'r').read()
    o = json.loads(c)
    return o

def sendBitcoinEmail(content):

    logging.basicConfig(filename='../logs/email.log', level=logging.DEBUG)
    fStorage = urlparse.parse_qs(content)
    try:
        len(fStorage)
    except Exception, err:
        return json.dumps({'status':'Error', 'error': 'No parameters specified.'})

    logging.info(fStorage)
    conf = readConf()
    emailSettings = conf.get('email','')
    if emailSettings == '':
        res = {'status':'Error', 'error': 'Email configuration not set.'}
        return json.dumps(res)

    email_host = emailSettings.get('host','')
    email_port = emailSettings.get('port','')
    e_error = ''
    if email_host == '': e_error = 'SMTP host not set. '
    if simpleemail.validport(email_port) != True:
        e_error += simpleemail.validport(email_port)
    if e_error != '':
        return json.dumps ({'status':'Error', 'error': e_error})

    emailUsername = emailSettings.get('username','')
    emailPassword = emailSettings.get('password','')

    e_error = ''
    #if emailUsername == '' and emailPassword != '':
    #    e_error = 'SMTP username set, but not SMTP password.'
    #if emailPassword == '' and emailUsername != '':
    #    e_error = 'SMTP username not set, but SMTP password is set.'
    if e_error != '':
        return json.dumps ({'status': 'Error', 'error':e_error})

    if "to" not in fStorage:
        res = {'status': 'Error', 'error':'No recipient given.'}
        return json.dumps(res)
    to = fStorage["to"][0]

    if "sender" not in fStorage:
        res = {'status':'Error', 'error': 'No sender given.'}
        return json.dumps(res)
    sender = fStorage['sender'][0]

    if "code" not in fStorage:
        res = {'status':'Error', 'error': 'No transaction code given.'}
        return json.dumps(res)
    code = fStorage['code'][0]

    emailConfig = {'email_host': email_host, 'email_port': email_port,
                'email_username': emailUsername, 'email_password': emailPassword}
    emailMsg = { 'sender': sender, 'to': sender,
        'subject': "You send bitcoins from Brollet",
        'message': "You sent bitcoins to {0}. Use the code below to recover the bitcoins with Brollet.\n\n{1}\n\n".format(to,code)}
    simpleemail.sendemail(emailConfig, emailMsg)
    emailMsg = { 'to': to, 'sender': sender,
            'subject': "Bitcoins from Brollet",
            'message': "You received bitcoins from {0}. Use the following code to redeem your bitcoins with Brollet.\n\n{1}\n\n".format(sender, code)}
    simpleemail.sendemail(emailConfig, emailMsg)
    return json.dumps({'status':'OK', 'message': 'Email sent.'})


def process(content):
    #print "Content-type: text/plain\n"
    #result = 0
    try:
        result = sendBitcoinEmail(content)
    except Exception, err:
        p_err = str(traceback.format_exc())
        result = json.dumps({'status':'Error', 'error': 'Email was not sent.', 'pythonerror': p_err})
    return result
