#!/usr/bin/env python

import json, sys
from scapy.all import *
try:
    # This import works from the project directory
    from scapy_http.http import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.http import *
from multiprocessing import Process
from multiprocessing import Event

class HTTPForwarder(Process):
    def __init__(self, interface):
        super(HTTPForwarder, self).__init__()
        self.interface = interface
        self.counter = 0
        self.__stopped = Event()

    def run(self):
        while not self.__stopped.is_set():
            print("HttpForwarder")
            sniff(iface = self.interface, filter="tcp port 80", prn = self.cb)
            self.__stopped.wait(5)

    def cb(self, pkt):
        if pkt.haslayer(HTTP):
            self.counter += 1
            if pkt.haslayer(HTTPRequest):
                return ('#{}: {} ==> {} {} @ {}'.format(self.counter,
                    pkt[IP].src,
                    pkt.getlayer(HTTPRequest).Method,
                    pkt.getlayer(HTTPRequest).Path,
                    pkt.getlayer(HTTPRequest).Host))
            elif pkt.haslayer(HTTPResponse) and pkt.haslayer(Raw):
                return ('#{}: {} ==> {}'.format(self.counter,
                    pkt[IP].src,
                    pkt.getlayer(HTTPResponse).getfieldval('Status-Line')))


    def stop(self):
        self.__stopped.set()

def main():
    obj = HTTPForwarder("eth0")
    obj.start()
    try:
        obj.join()
    except KeyboardInterrupt:
        obj.stop()

if __name__ == "__main__":
    main()
