from __future__ import print_function
import logging
logging.getLogger("httplib").setLevel(logging.CRITICAL)
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
from scapy.all import *
from BaseHTTPServer import HTTPServer
from SocketServer import ThreadingMixIn
from HTTPServer import ProxyRequestHandler as ProxyRequestHandler


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    def handle_error(self, request, client_address):
        return HTTPServer.handle_error(self, request, client_address)


class Proxy:
    def __init__(self, params, config):
        self.params = params
        self.config = config
        self.serv_address = ('', self.params.port)
        ProxyRequestHandler.protocol_version = "HTTP/1.1"
        self.zia = ThreadingHTTPServer(self.serv_address, ProxyRequestHandler)
        self.socket = self.zia.socket.getsockname()
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports {}".format(self.params.port))

    def go(self):
        print ('\033[92m[+]\tStarting HTTP server on port ', self.socket[1], '\033[0m')
        self.zia.serve_forever()

    def stop(self):
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        os.system('iptables -t nat -F')
        self.zia.socket.close()
        print ('\033[94m[-]\tIptables d3l3t3d !\033[0m')