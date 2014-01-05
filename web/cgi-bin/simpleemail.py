#!/usr/bin/env python
import smtplib

def sendemail(emailConfig, emailMsg):
    smtpserver = smtplib.SMTP(str(emailConfig['email_host']), str(emailConfig['email_port']))
    smtpserver.ehlo()
    if emailConfig['email_username'] != '':
        smtpserver.starttls()
        smtpserver.ehlo()
        smtpserver.login(emailConfig['email_username'], emailConfig['email_password'])
    header = "To:{0}\nFrom:{1}\nSubject:{2}\n\n".format(
            emailMsg['sender'], emailMsg['to'], emailMsg['subject'])
    msg = header + emailMsg['message']
    smtpserver.sendmail(emailMsg['sender'], emailMsg['to'], msg)

def validport(n):
    #if (n == None or n==''): return 'SMTP port not set.'
    #if( not n.isdigit()): return 'SMTP port must be an integer.'
    return True
