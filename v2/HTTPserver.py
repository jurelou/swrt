from __future__ import print_function
import urllib2
import httplib
import ssl
import urlparse
import threading
from scapy.all import *
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO


class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 10
    lock = threading.Lock()
    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_GET(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None
        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)
        
        url = urlparse.urlsplit(req.path)
        scheme = url.scheme
        netloc = url.netloc
        path = (url.path + '?' + url.query if url.query else url.path)        
        setattr(req, 'headers', self.clean_headers(req.headers))
        try:
            origin = (scheme, netloc)
            if  origin is not self.tls.conns:
                if scheme == 'https':
                    self.tls.conns = httplib.HTTPSConnection( netloc, timeout=self.timeout)
                else:
                    self.tls.conns = httplib.HTTPConnection(netloc, timeout=self.timeout)

            self.tls.conns.request(self.command, path, req_body, dict(req.headers))
            res = self.tls.conns.getresponse()
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', {10: 'HTTP/1.0', 11: 'HTTP/1.1'})
            res_body = res.read()
        except Exception as e:
            print ("Exception ---> {}".format(e))
            return
        setattr(res, 'headers', self.clean_headers(res.headers))
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

    def clean_headers(self, headers):
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate',
                      'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]
        del headers['Accept-Encoding'] # mhhhhhhhhhHHH .........
        return headers
