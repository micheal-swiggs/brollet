#!/usr/bin/env python
import sys
import os
import json
import traceback
import logging
import simpleemail
try:
    import ssl
except Exception:
    print "no SSL"
    sys.exit()


print "Content-type: text/plain\n"

logging.basicConfig(filename='../../logs/testemail.log', level=logging.DEBUG)

if not _have_ssl:
    print "no SSL"
    sys.exit()



try:
#    conlen = int(os.environ['CONTENT_LENGTH'])
#    rawinp = sys.stdin.read(conlen)
#     rawinp = '{"emailConfig": {"email_port": 465, "email_username": "ezwallet1@gmail.com", "email_password": "EZ1Walle", "email_host": "smtp.gmail.com"}, "emailMsg": {"to": "arimaa_game@yahoo.com", "message": "testing 123", "sender": "osyed1@gmail.com", "subject": "EZWallet test email."}}'
     rawinp = '{"emailConfig": {"email_port": 587, "email_username": "ezwallet1@gmail.com", "email_password": "EZ1Walle", "email_host": "smtp.gmail.com"}, "emailMsg": {"to": "arimaa_game@yahoo.com", "message": "testing 123", "sender": "osyed1@gmail.com", "subject": "EZWallet test email."}}'
except Exception:
    rawinp = sys.stdin.read()
print >> sys.stderr, rawinp

if rawinp == '':
    res = {'status':'Error', 'error': 'No input given.'}
    print json.dumps (res)
    sys.exit()
data = json.loads(rawinp)
logging.info(data);
emailConfig = data['emailConfig']
emailMsg = data['emailMsg']

try:
    simpleemail.sendemail(emailConfig, emailMsg)
except Exception, err:
    p_err = str(traceback.format_exc())
    print json.dumps({'status': 'Error', 'error': 'Email was not sent.', 'pythonerror': p_err})
    sys.exit(0)

print json.dumps({'status':'OK', 'message': 'Email sent.'})


