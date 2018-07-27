#!/usr/local/bin/python3
"""
webhook.py

Python3 Webhook to receive SPLUNK alert data on port 5005

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
def webhook():
    """ webhook config and actions """
    if not request.json:
        abort(400)    
    if request.method == 'POST':
        ipaddress = request.remote_addr
        data = request.get_json(force=True)
        print(data["search_name"])
        for splunkitem in data["result"]:
            print(data["result"][splunkitem])
        return '', 200
    else:
        return """<title>404 Not Found</title><h1>Not Found</h1><p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>""", 404

if __name__ == '__main__':
    """ Main part of the script"""
    # Start up the Flask Listener
    app.debug = True
    app.run(host = '0.0.0.0',port=5005)



