#!/usr/bin/env python

from scapy.all import *
import sys

class ARPPoisoner:
    def __init__(self, victimIp = '0.0.0.0', interface = 'eth0'):
        self.victimIp = victimIp
        self.inteface = 'eth0'

    def get_hwaddr_victim_ip(self):
        resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.victimIp), retry=2, timeout=10)
        for sended, received in resp:
            if received[ARP].hwsrc:
                return received[ARP].hwsrc
        return;

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print ('usage: ' + sys.argv[0] + ' VICTIM_IP USURPED_IP')
        exit(0);
    poisoner = ARPPoisoner(sys.argv[1], sys.argv[2]);
    print(spoofer.get_hwaddr_victim_ip())
