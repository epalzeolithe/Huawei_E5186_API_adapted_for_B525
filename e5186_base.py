#!/usr/local/bin/python3
"""
e5186_base.py

Python3 Scripts to interact with Huawei E5186

David Pollard
Information Security Consultant
UnshakableSalt.com
26 July 2018

# - https://blog.hqcodeshop.fi/archives/259-Huawei-E5186-AJAX-API.html
# - http://www.bez-kabli.pl/viewtopic.php?t=43279
# - http://forum.jdtech.pl/Watek-hilink-api-dla-urzadzen-huawei?pid=29774#PIN
# - http://forum.jdtech.pl/Watek-hilink-api-dla-urzadzen-huawei?pid=29790#autopin

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
import argparse
import re
import xml.etree.ElementTree as ET
from lxml import etree

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

def logout(session):
    xml = """<?xml version:"1.0" encoding="UTF-8"?><request><Logout>1</Logout></request>"""
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/device/control'
    response = session.post(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True
    else:
        message_sent = False
    return message_sent

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
    messagedate = datetime.now().isoformat(sep=' ', timespec='seconds')
    smscontent = '<?xml version = "1.0" encoding = "UTF-8"?>'
    smscontent += '<request>'
    smscontent += '<Index>-1</Index>'
    smscontent += '<Phones><Phone>' + phonenumber + '</Phone></Phones>'
    smscontent += '<Sca></Sca>'
    smscontent += '<Content>' + message + '</Content>'
    smscontent += '<Length>' + str(len(message)) + '</Length>'
    smscontent += '<Reserved>1</Reserved>' #SMS_TEXT_MODE_7BIT =1
    smscontent += '<Date>' + messagedate + '</Date>'
    smscontent += '</request>'

    return smscontent

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

build_text_list = etree.XPath("//text()")

def errcode(rep):
    code = 0
    root = ET.fromstring(rep.text)
    error = 0

    for results in root.iter('error'):
        error = results.text

    if error:
        for results in root.iter('code'):
            code = results.text

    return code


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
        if errcode(response):
            print("Failed to send SMS - Error : " + errcode(response))
            print(smstosend)
            message_sent = False
    else:
        message_sent = False
    return message_sent



def check_uk_mobile(phonenumber):
    # Check to see if the phone number is correct for the UK
    # ie,  correct length and starts 07 or +447
    # REQUIRED : import re
    rule = re.compile(r'^(07\d{9}|\+?447\d{9})$')
    if rule.search(phonenumber):
        return True
    else:
        return False

def reboot(session):

    xml = """<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>"""
    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/device/control'
    response = session.post(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True

    else:
        message_sent = False
    return message_sent

#10000000000011010101 = HEX 800D5 = <LTEBand>800D5</LTEBand>
#binary from right to left 1-20
#00000000000000000001 = only 2100 MHZ = Band 1 = <LTEBand>00001</LTEBand>
#00000000000000000100 = only 1800 MHZ = Band 3 = <LTEBand>00004</LTEBand>
#00000000000000010000 = only 850 MHZ = Band 5 = <LTEBand>00010</LTEBand>
#00000000000001000000 = only 2600 MHZ = Band 7 = <LTEBand>00040</LTEBand>
#00000000000010000000 = only 900 MHZ = Band 8 = <LTEBand>00080</LTEBand>
#10000000000000000000 = only 800 MHZ = Band 20 = <LTEBand>80000</LTEBand>


LTE_800 = "80000" # Band 20
LTE_850 = "10" # Band 5
LTE_900 = "80" # Band 8
LTE_1800 = "4"  # Band 3
LTE_2100 = "1"  # Band 1
LTE_2600 = "40"  # Band 7
LTE_1800_2600 = "44"
LTE_AUTO = "800C5" # Band 1, 3, 7, 8, 20
LTE_FULL = "800D5" # Band 1, 3, 5, 7, 8, 20


def changeLTE(session):
    # xml = """<?xml version="1.0" encoding="UTF-8"?><request><Control>1</Control></request>"""

    targetLTE = LTE_FULL

    xml = """<?xml version="1.0" encoding="UTF-8"?>
        <response>
        <NetworkMode>03</NetworkMode>
        <NetworkBand>3FFFFFFF</NetworkBand>
        <LTEBand>""" + targetLTE + """</LTEBand>
        </response>"""

    (session, sessionid, token) = get_sessionid_nexttoken(session)
    headers = {'Content-Type': 'text/xml; charset=UTF-8',
               '__RequestVerificationToken': token,
               'Cookie': sessionid
               }
    api_url = BASEURL + '/api/net/net-mode'
    response = session.post(
        api_url, data=xml, headers=headers, cookies=session.cookies)
    if response.status_code == 200:
        message_sent = True
        print ("LTE Changed to "+targetLTE)
    else:
        message_sent = False
    return message_sent

def main():
    """ Main part of the script"""
    # Connect and initiate session on the device
    session = requests.Session()
    loggedin = login(session)
    if loggedin:
        # reboot(session)
        print("Logged on "+BASEURL)

        #changeLTE(session)

        # Create the message to send
        parser = argparse.ArgumentParser()
        parser.add_argument("smsnumber", help="The number you want to send to")
        parser.add_argument("smsmessage", help="The message you want to send")
        args = parser.parse_args()
        smsnumber = args.smsnumber
        smsmessage = args.smsmessage[:139]
        # if not check_uk_mobile(args.smsnumber):
        #           print("Invalid Phone Number")
        #           quit()
        #messagedate = datetime.now().isoformat(sep=' ', timespec='minutes')
        #smsmessage = str(messagedate) + smsmessage
        smstosend = contructmessage(smsnumber, smsmessage)
        if send_sms(session, smstosend):
            print("Message Sent to " + smsnumber)
        if logout(session):
            print("Logout")
        else :
            print("Logout failed")
    else:
        print("Login Failure")


# # Main # #
main()
############
