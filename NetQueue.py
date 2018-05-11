#!/usr/bin/env python

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
    def __init__(self, params):
        super(NetQueue, self).__init__()
        self.counter = 0
        self.q = nfqueue.queue()
        self.q.open()
        self.q.bind(socket.AF_INET)
        self.params = params
        self.DNSworker = DNSproxy(params)
        self.HTTPworker = HTTPproxy(params)
    
    @staticmethod
    def accept(original_pkt, spoofed_pkt):
        original_pkt.set_verdict(nfqueue.NF_ACCEPT)
        print "<-- accepted"
    @staticmethod
    def drop(original_pkt, spoofed_pkt):
        original_pkt.set_verdict(nfqueue.NF_DROP)
        print " <-- dropped"

    @staticmethod
    def modify(original_pkt, spoofed_pkt):
        #pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed), len(spoofed))
        print " <-- modify"

    def cb(self, payload):
        data = payload.get_data()
        pkt = IP(data)
        meth_map = {0 : self.accept,
                    1 : self.modify,
                    2 : self.drop
        }
        ret = {'meth': 0}
        if pkt.haslayer(DNS):
            ret = self.DNSworker.call(pkt)
        elif pkt.haslayer(HTTP):
            ret = self.HTTPworker.call(pkt)
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
