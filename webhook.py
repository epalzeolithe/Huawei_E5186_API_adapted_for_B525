#!/usr/local/bin/python3
"""
webhook.py

Python3 Webhook to receive data on port 5005

REQUIRES :  flask

David Pollard
Information Security Consultant
UnshakableSalt.com
26 July 2018

"""
from ipaddress import ip_network, ip_address
from flask import Flask, request, abort

app = Flask("webhook")
@app.route('/webhook', methods=['POST'])

def valid_ip(clientipaddress):
    """ Check to make sure this is a local connection """
    net = ip_network("192.168.1.0/24")
    if clientipaddress in net:
        return True
    else:
        return False

def webhook():
    """ webhook config and actions """    
    if not valid_ip(request.remote_addr):
        return """<title>403 Forbidden</title><h1>Forbidden</h1><p>Go stand in a corner monkeyboy</p>""", 403
    if request.method == 'POST':
        print(request.json)
        return '', 200
    else:
        return """<title>404 Not Found</title><h1>Not Found</h1><p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>""", 404

if __name__ == '__main__':
    """ Main part of the script"""
    # Start up the Flask Listener
    app.debug = True
    app.run(host = '0.0.0.0',port=5005)


down vote
In Python 3.3 and later, you should be using the ipaddress module.




