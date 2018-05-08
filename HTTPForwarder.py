#!/usr/bin/env python

import json, sys
from scapy.all import *
try:
    from scapy_http.http import *
except ImportError:
    from scapy.layers.http import *
from multiprocessing import Process
from multiprocessing import Event

class HTTPForwarder(Process):
    def __init__(self, interface, router):
        super(HTTPForwarder, self).__init__()
        self.interface = interface
        self.counter = 0
        self.router = router
        self.__stopped = Event()

    def run(self):
        sniff(iface = self.interface, filter="tcp", prn = self.cb)
    

    def forwardHTTP(self, pkt):
        print "ooooooooooooooooooo\n", pkt[IP].src, " -> ", pkt[IP].dst, "\n\n", pkt.show(), "\nooooooooooooooo\n"


    def forwardTCP(self, pkt):
        #print pkt.show()

        forged =IP(dst=pkt[IP].dst, src = pkt[IP].src)/TCP()
        forged[TCP] = pkt[TCP]
        response = sr1(forged, verbose = 0)
        spfAns = IP(src = pkt[IP].dst, dst=pkt[IP].src)/TCP()
        
        spfAns[TCP] = response[TCP]

        spfAns[TCP].dport = pkt[TCP].sport
        resp = sr1(spfAns, verbose = 0)
        if resp.haslayer(HTTP):
            self.forwardHTTP(resp)
        else:
            print "!!!!!!!!\n!!!!!\n"
        return 
    
    def cb(self, pkt):
        if pkt.haslayer(HTTP):
            print "C GAGNEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\nEEEEEEEEEEEEEEEEEE"
            sys.exit(0)
            return
        print "----------------------------------\n",pkt[IP].src ," -> ", pkt[IP].dst, "\n--------------------------------------\n"
        self.forwardTCP(pkt)
        return
        

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
    obj = HTTPForwarder("ens33", "192.168.1.1")
    obj.start()
    try:
        obj.join()
    except KeyboardInterrupt:
        obj.stop()

if __name__ == "__main__":
    main()
