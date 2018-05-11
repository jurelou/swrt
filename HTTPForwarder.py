#!/usr/bin/env python

import json, sys
import nfqueue
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
        self.q = nfqueue.queue()
        self.q.open()
        self.q.bind(socket.AF_INET)
        self.q.set_callback(self.cb)
        self.q.create_queue(0)
        self.router = router
        self.__stopped = Event()

    def run(self):
        print '\033[92m[+]\tStarting HTTP forwarder\033[0m'
        os.system('iptables -A FORWARD -j NFQUEUE')
        try:
            self.q.try_run()
        except KeyboardInterrupt:
            self.restore()
            return; 

    def restore(self):
        print '\033[94m\n[-]\tStopping HTTP forwarder\033[0m'
        self.q.unbind(socket.AF_INET)
        self.q.close()
        os.system('iptables -F')
        os.system('iptables -X')

    def cb(self, pkt):
        data = pkt.get_data()
        spoofed = IP(data)
        if spoofed.haslayer(DNS):
            
            print "-- RECEIVED ", self.counter, " --\n", spoofed.show(), "\n-----\n"
        else:
            print "no dns\n"
        self.counter += 1
        pkt.set_verdict(nfqueue.NF_ACCEPT)
        
        #pkt.set_verdict(nfqueue.NF_DROP)
        '''
            pour drop les paquets
        pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed), len(spoofed))
            pour modif
        '''
   


        return;

def main():
    obj = HTTPForwarder("ens33", "192.168.1.1")
    obj.start()

if __name__ == "__main__":
    main()
