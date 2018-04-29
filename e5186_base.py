#!/usr/local/bin/python3
"""
e5186_base.py

Python3 Scripts 
to interact with Huawei E5186

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

def login():
    """ Log into the Huawei Router and get cookie token pair """
    session = requests.Session()
    (sessionid, token, sessioncookies) = get_sessionid_nexttoken(session)
    hashedpassword = login_data(token)
    post_data = '<?xml version = "1.0" encoding = "UTF-8"?>\n'
    post_data += '<request><Username>' + USERNAME + '</Username>\n'
    post_data += '<Password>' + hashedpassword + '</Password>\n'
    post_data += '<password_type>4</password_type></request>\n'
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
              }
    # print(post_data) # Know the password above works now
    api_url = BASEURL + '/api/user/login'
    logonresponse = session.post(api_url, data=post_data, headers=headers, cookies=session.cookies)
    # Should now be logged in,  lets check
    # api_url = BASEURL + '/api/user/state-login'
    # verifyresponse = session.get(api_url)
    # print(verifyresponse.text)
    # <State>0</State> is logged in user.
    # Need a new token before issuing a config/update
    (sessionid, token, sessioncookies) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
              }
    # Create the message to send
    api_url = BASEURL + '/api/sms/send-sms'
    mynumber = '+447788974296'
    mymessage = 'Sending this amazing message'
    smstosend = contructmessage(mynumber, mymessage)
    sendsms_response = session.post(
        api_url, data=smstosend, headers=headers, cookies=sessioncookies)
    return

def login_data(sessiontoken):
    """ return the authentication credential """
    password = b64_sha256(PASSWORD)
    authstring = USERNAME + password + sessiontoken
    authcred = b64_sha256(authstring)
    return authcred

def get_sessionid_nexttoken(session):
    """ Every system call requires a new token """
    token_response = session.get(BASEURL + '/api/webserver/SesTokInfo')
    if token_response.status_code == 200:
        root = ET.fromstring(token_response.text)
        for results in root.iter('SesInfo'):
            sessionid = results.text
        for results in root.iter('TokInfo'):
            token = results.text
        sessioncookies = token_response.cookies
    return(sessionid, token, sessioncookies)

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

def main():
    """ Main part of the script"""
    # Connect and initiate session on the device
    print("")
    login()
    # if Session then send

def b64_sha256(data: str):
    """ This is the one that works, do not remove """
    s256 = hashlib.sha256()
    s256.update(data.encode('utf-8'))
    dgs256 = s256.digest()
    hs256 = binascii.hexlify(dgs256)
    return base64.urlsafe_b64encode(hs256).decode('utf-8', 'ignore')

# # Main # #
main()
############
