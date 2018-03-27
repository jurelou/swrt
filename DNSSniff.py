#!/usr/bin/python2.7 
 
import sys, time 
from scapy.all import * 
from multiprocessing import Process
 
class DNSSniffer(Process): 
  def __init__(self, i):
    super(DNSSniffer, self).__init__()
    self.interface = i
    self.enableIpForwarding()
  
  def run(self):
    while(True):
      sniff(iface = self.interface, filter = 'port 53', prn = self.cb) 
  
  def stop(self): 
    #self.e.set() 
    print " -- Stopping DNSSniff" 
   
  def cb(self, pkt):
    if pkt.haslayer(DNSQR):
      print pkt[IP].src , "->" , pkt[IP].dst , "(" + pkt.getlayer(DNS).qd.qname, ")"
      '''
      send(IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
          DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
          an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to)),verbose=0)
      '''
  def enableIpForwarding(self):
    ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipf_read = ipf.read()
    if ipf_read != '1\n':
        ipf.write('1\n')
    ipf.close()