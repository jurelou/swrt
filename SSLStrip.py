#!/usr/bin/python2.7 
 
from __future__ import print_function

class SSLStrip:
    def modify_request(self, header, body):
        pass
    def modify_response(self, req, res, body):
        if res.header:
            for h in res.headers:
                if "https://" in res.headers[h]:
                    res.headers[h].replace("https://","http://s")