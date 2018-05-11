#!/usr/bin/python2.7 

from __future__ import print_function
import sys, time 
from scapy.all import * 
from multiprocessing import Process
import netifaces

COL = '\033[93m'
END = '\033[0m'

class HTTPproxy(Process): 
  def __init__(self, params):
    super(HTTPproxy, self).__init__()
    self.counter = 0
    self.interface = params.interface
    self.conf = params.conf
    self.myip = netifaces.ifaddresses(self.interface)[2][0]['addr']
    self.mymac = netifaces.ifaddresses(self.interface)[17][0]['addr']
    self.router = params.gateway
    print ('\033[92m[+]\tStarting HTTP proxy\033[0m')

  def call(self, pkt):
    print ("HTTP / ", end="")
    print (pkt.show())
    '''
    pkt[TCP].payload = str(pkt[TCP].payload).replace("ABC","GET")
    pkt[IP].ttl = 40
    print ('Data: '+ str(pkt[TCP].payload))
    print ('TTL: ' + str(pkt[IP].ttl))
    print (pkt.show())
    del pkt[IP].chksum
    del pkt[TCP].chksum
    return {'meth': 2, 'spoofed_pkt': pkt}    
    '''
    return {'meth': 0}
  def stop(self): 
    print ('\033[94m[-]\tStopping HTTP proxy\033[0m')