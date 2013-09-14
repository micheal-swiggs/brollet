#!/usr/bin/env python
import sys
import os
import json
import smtplib
import traceback
import logging

def sendemail(emailConfig, emailMsg):
    smtpserver = smtplib.SMTP(emailConfig['email_host'], emailConfig['email_port'])
    smtpserver.ehlo()
    if emailConfig['email_username'] != '':
        smtpserver.starttls()
        smtpserver.ehlo()
        smtpserver.login(emailConfig['email_username'], emailConfig['email_password'])
    header = "To:{0}\nFrom:{1}\nSubject:{2}\n\n".format(
            emailMsg['sender'], emailMsg['to'], emailMsg['subject'])
    msg = header + emailMsg['message']
    smtpserver.sendmail(emailMsg['sender'], emailMsg['to'], msg)


