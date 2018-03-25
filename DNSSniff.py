#!/usr/bin/python2.7 
 
import threading, time 
from scapy.all import * 
 
class DNSSniffer(threading.Thread): 
  def __init__(self, rIp, interface): 
    threading.Thread.__init__(self) 
    self.e = threading.Event() 
    self.rIp = rIp 
    self.interface = interface 
    self.kill_received = False 
  
  def run(self): 
    while not self.kill_received: 
      DNSSniffer.sniff(self)     
 
  def stop(self): 
    self.e.set() 
    print " -- Stopping DNSSniff" 
   
  def printDNS(self, packet): 
    if IP in packet: 
      ip_src = packet[IP].src 
      ip_dest = packet[IP].dst 
      if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0: 
        print ip_src + " -> " + ip_dest + " (" + packet.getlayer(DNS).qd.qname + ")" 
     
  def sniff(self): 
    sniff(iface = self.interface, filter = 'port 53', prn = self.printDNS, stop_filter=lambda p: self.e.is_set()) 