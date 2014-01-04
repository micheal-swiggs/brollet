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
     rawinp = '{"emailConfig": {"email_port": 587, "email_username": "brollet.test@gmail.com", "email_password": "1Brolle", "email_host": "smtp.gmail.com"}, "emailMsg": {"to": "testuser@yahoo.com", "message": "testing 123", "sender": "testuser@gmail.com", "subject": "Brollet test email."}}'
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


