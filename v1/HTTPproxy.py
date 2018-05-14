#!/usr/bin/python2.7 

from __future__ import print_function
import sys, time 
from scapy.all import *
from netfilterqueue import NetfilterQueue
from multiprocessing import Process
import netifaces
try:
    from scapy_http.http import *
except ImportError:
    from scapy.layers.http import *

COL = '\033[93m'
END = '\033[0m'

class HTTPproxy(Process): 
  def __init__(self, params):
    super(HTTPproxy, self).__init__()
    self.interface = params.interface
    self.conf = params.conf
    self.myip = netifaces.ifaddresses(self.interface)[2][0]['addr']
    self.mymac = netifaces.ifaddresses(self.interface)[17][0]['addr']
    self.router = params.gateway
    print ('\033[92m[+]\tStarting HTTP proxy\033[0m')

  @staticmethod
  def forge_reply(pkt):
        spoofed = pkt
        '''
        del spoofed[IP].chksum
        del spoofed[TCP].chksum
        '''
        spoofed[TCP].payload = str(spoofed[TCP].payload).replace("GET", "ABC")    
        del spoofed[IP].chksum
        del spoofed[TCP].chksum
        return(spoofed)
  
  def call(self, payload):
    pkt = payload.get_payload()
    ip = IP(pkt)
    tmp = pkt
    print("mdrrrr")
    #print(ip.show2())
    if ip.haslayer(HTTP):
        print ("HTTP / ", end="")
        if ip.haslayer(HTTPRequest):
            return {'meth':0} 
        elif ip.haslayer(HTTPResponse):
            print ("RESPONSE / ", end="")
            #ip[TCP].payload = str(ip[TCP].payload).replace("BROKEN", "ABCDEF")
            #print("initial checksums:", ip.chksum , " ", ip[TCP].chksum)
            #del ip.chksum
            #del ip[TCP].chksum 
            #print(ip[TCP].show2())
            #print("end checksums:", ip.chksum , " ", ip[TCP].chksum)
            #print("ip : ", len(ip), " tcp:", len(ip[TCP]), " forged:")
            print("=>", payload)
            #print (len(pkt[TCP]), " -- ", len(tmp[TCP]), " --", len(ip[TCP]))
            return {'meth':1, 'spoofed_pkt': pkt} 
        '''
        sendp(Ether()/IP(dst="poc.argos.sh")/TCP()/"GET / HTTP/1.0\r\nHost: poc.argos.sh\r\nAccept: */*\r\n\r\n")
        '''   
    else:
        print("TCP", end="")
    return {'meth': 0}

  def stop(self): 
    print ('\033[94m[-]\tStopping HTTP proxy\033[0m')