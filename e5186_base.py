#!/usr/local/bin/python3
"""
e5186_base.py

Python3 Scripts to interact with Huawei E5186

David Pollard
Information Security Consultant
UnshakableSalt.com
26 April 2018

"""
try:
    # Load config from the local e5186_config.py file
    from e5186_config import BASEURL, USERNAME, PASSWORD
except ImportError:
    print("No config file")
    quit()
import hashlib
import base64
import binascii
import xml.etree.ElementTree as ET
from datetime import datetime
import requests

def login(session):
    """ Log into the Huawei Router and get cookie token pair """
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    hashedpassword = login_data(token)
    post_data = '<?xml version = "1.0" encoding = "UTF-8"?>\n'
    post_data += '<request><Username>' + USERNAME + '</Username>\n'
    post_data += '<Password>' + hashedpassword + '</Password>\n'
    post_data += '<password_type>4</password_type></request>\n'
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
              }
    api_url = BASEURL + '/api/user/login'
    response = session.post(api_url, data=post_data, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        loggedin = loggedin_check(session)
    else:
        loggedin = False
    return loggedin

def login_data(sessiontoken):
    """ return the authentication credential """
    password = b64_sha256(PASSWORD)
    authstring = USERNAME + password + sessiontoken
    authcred = b64_sha256(authstring)
    return authcred

def b64_sha256(data: str):
    """ This is the one that works, do not remove """
    s256 = hashlib.sha256()
    s256.update(data.encode('utf-8'))
    dgs256 = s256.digest()
    hs256 = binascii.hexlify(dgs256)
    return base64.urlsafe_b64encode(hs256).decode('utf-8', 'ignore')

def get_sessionid_nexttoken(session):
    """ Every system call requires a new token """
    response = session.get(BASEURL + '/api/webserver/SesTokInfo')
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        for results in root.iter('SesInfo'):
            sessionid = results.text
        for results in root.iter('TokInfo'):
            token = results.text
    return(session, sessionid, token)

def contructmessage(phonenumber, message):
    """ Constuct the XML message ready to send"""
    messagedate = datetime.now().isoformat(sep=' ', timespec='minutes')
    smscontent = '<?xml version = "1.0" encoding = "UTF-8"?>'
    smscontent += '<request>'
    smscontent += '<Index>-1</Index>'
    smscontent += '<Phones><Phone>' + phonenumber + '</Phone></Phones>'
    smscontent += '<Sca/>'
    smscontent += '<Content>' + message + '</Content>'
    smscontent += '<Length>' + str(len(message)) + '</Length>'
    smscontent += '<Reserved>1</Reserved>'
    smscontent += '<Date>' + messagedate + '</Date>'
    smscontent += '<SendType>0</SendType></request>'
    return smscontent

def send_sms(session, smstosend):
    """ send a constructed sms message """
    # Need a new token before issuing a config/update
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
              }
    api_url = BASEURL + '/api/sms/send-sms'
    response = session.post(
        api_url, data=smstosend, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True
    else:
        message_sent = False
    return message_sent

def loggedin_check(session):
    """ validate if we are logged in """
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    api_url = BASEURL + '/api/user/state-login'
    response = session.get(api_url)
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        for results in root.iter('State'):
            session_state = results.text
        if session_state == "0":
            # 0 is logged in,  -1 is logged out
            loggedin = True
        else:
            loggedin = False
    else:
        loggedin = False
    return loggedin


def main():
    """ Main part of the script"""
    # Connect and initiate session on the device
    session = requests.Session()
    loggedin = login(session)
    if loggedin:
        # Create the message to send
        mynumber = '+447788974296'
        messagedate = datetime.now().isoformat(sep=' ', timespec='minutes')
        mymessage = str(messagedate) + ' nice messgae'
        smstosend = contructmessage(mynumber, mymessage)
        if send_sms(session, smstosend):
            print("Message Sent to " + mynumber)
    else:
        print("Log in Failure")
    # if Session then send

# # Main # #
main()
############
