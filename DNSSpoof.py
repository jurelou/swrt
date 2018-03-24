#!/usr/bin/python2.7

from scapy.all import *
import sys

class DNSSpoofer:
    def __init__(self, victimIp = '0.0.0.0', interface = 'ens33'):
        self.victimIp = victimIp
        self.interface = interface
    
    def printDNS(self, packet):
    	if IP in packet:
    		ip_src = packet[IP].src
    		ip_dest = packet[IP].dst
    		if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
    			print ip_src + " -> " + ip_dest + " (" + packet.getlayer(DNS).qd.qname + ")"
    
    def sniff(self):
    	sniff(iface = self.interface, filter = 'port 53', prn = self.printDNS, store = 0)
    	print "mdr"