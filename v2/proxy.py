#!/usr/bin/env python2.7
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import SocketServer

DATA_DIR = os.getcwd()

debug = True
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
            return HTTPServer.handle_error(self, request, client_address)

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

def Proxy(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer):
    server_address = ('', port)

    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    httpd.serve_forever()

'''
def Proxy(HandlerClass=ProxyRequestHandler, aaa=ThreadingHTTPServer, protocol="HTTP/1.1"):
    server_address = ('', 8080)

    HandlerClass.protocol_version = protocol
    httpd = aaa(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "\n[+] Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()
'''


'''
class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)
        cur_thread = threading.current_thread()
        response = "{}: {}".format(cur_thread.name, data)
        self.request.sendall(response)
class Proxy:
	def __init__(self, config, params):
		self.params = params
		self.config = config
		self.root_path = DATA_DIR
		self.zia = ThreadedTCPServer(('', 8080), ThreadedTCPRequestHandler)
		
		ip, port = self.zia.server_address
		print ip, port
		server_thread = threading.Thread(target=self.zia.serve_forever)
		server_thread.daemon = True
		server_thread.start()
		self.client(ip, port, "Hello World 1")
		self.client(ip, port, "Hello World 2")
		self.client(ip, port, "Hello World 3")
	
	def go(self):
		print("lol")
	
	def client(self, ip, port, message):
	    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    sock.connect((ip, port))
	    try:
	        sock.sendall(message)
	        response = sock.recv(1024)
	        print "Received: {}".format(response)
	    finally:
	        sock.close()		

	def stop():
		server.shutdown()
		server.server_close()			
'''