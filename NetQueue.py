#!/usr/bin/env python

from __future__ import print_function
import sys, nfqueue
from scapy.all import *
from multiprocessing import Process
from multiprocessing import Event
try:
    from scapy_http.http import *
except ImportError:
    from scapy.layers.http import *

from DNSproxy import DNSproxy
from HTTPproxy import HTTPproxy

class NetQueue(Process):
    def __init__(self, params, conf):
        super(NetQueue, self).__init__()
        self.counter = 0
        self.q = nfqueue.queue()
        self.q.open()
        self.q.bind(socket.AF_INET)
        self.params = params
        self.params.conf = conf
        self.DNSworker = DNSproxy(self.params)
        self.HTTPworker = HTTPproxy(self.params)
    
    @staticmethod
    def accept(original_pkt, spoofed_pkt):
        original_pkt.set_verdict(nfqueue.NF_ACCEPT)
        print (" <-- accepted")
    @staticmethod
    def drop(original_pkt, spoofed_pkt):
        original_pkt.set_verdict(nfqueue.NF_DROP)
        print (" <-- dropped")

    @staticmethod
    def modify(original_pkt, spoofed_pkt):
        #pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed), len(spoofed))
        print (" <-- modify")

    def cb(self, payload):
        data = payload.get_data()
        pkt = IP(data)
        proto = pkt.proto
        print("New packet from: " + pkt.src + " to: " + pkt.dst + " / ", end="");
        meth_map = {0 : self.accept,
                    1 : self.modify,
                    2 : self.drop
        }
        ret = {'meth': 0}    
        if proto is 0x06:
            print ("TCP", end="")
        elif proto is 0x11:
            if pkt[UDP].dport is 53:
                ret = self.DNSworker.call(pkt)
            elif pkt[UDP].sport is 53:
                print ("DNS answer", end="")
        elif proto is 0x01:
            print ("ICMP", end="")
        elif proto is 0x29:
            print ("IPv6", end="")
        elif proto is 0x2b:
            print ("IPv6-Route", end="")
        
        if not 'spoofed_pkt' in ret:
            ret['spoofed_pkt'] = ''
        meth_map[ret['meth']](payload, ret['spoofed_pkt'])

    def run(self):
        self.q.set_callback(self.cb)
        self.q.create_queue(0)
        os.system('iptables -A FORWARD -j NFQUEUE')
        try:
            self.q.try_run()
        except KeyboardInterrupt:
            self.restore()
            return; 

    def restore(self):
        self.q.unbind(socket.AF_INET)
        self.q.close()
        self.HTTPworker.stop()
        self.DNSworker.stop()
        os.system('iptables -F') # oops ...
        os.system('iptables -X') # oops ...
        return;

def main():
    obj = NetQueue("ens33", "192.168.1.1")
    obj.start()

if __name__ == "__main__":
    main()
