#!/usr/bin/env python2.7
import os, sys, socket, fcntl, struct, traceback
import DNSConf
from time import sleep
import argparse
from scapy.all import *


BLUE = '\033[94m'
END = '\033[0m'
port = 8080

class SWRT(object):
	def __init__(self):
		args = 0
		parser = argparse.ArgumentParser()
		parser.add_argument("-d", "--debug", help="increase output verbosity", action="store_true", required=False)
		parser.add_argument('-i', action='store', default="ens33", dest='interface', help='Store the interface', required=False)
		parser.add_argument('-t', action='store', dest='target', help='Store a target IP address', required=True)
		parser.add_argument('-r', action='store', default="192.168.1.1", dest='gateway', help='Store the gateway IP address', required=False)
		parser.add_argument('-c', action='store', dest='conf', default='./conf.json', help='Store path/to/conf.json', required=False)
		parser.add_argument('-p', action='store', default="8080", dest='port', help='Store the port', required=False)
		self.args = parser.parse_args()

		def nic_ip(interface):
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
		
		def nic_mac(interface):
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

		self.hostIP = nic_ip(self.args.interface)
		self.hostMAC = nic_mac(self.args.interface)
		self.targetIP = self.args.target
		
		self.targetMAC = resolve_mac(self.targetIP)
		self.gatewayIP = self.args.gateway
		self.gatewayMAC = resolve_mac(self.gatewayIP)
		print "[+] MY IP: {}".format(self.hostIP)		
		print "[+] MY MAC {}".format(self.hostMAC)
		print "[+] VICTIM IP {}".format(self.targetIP)
		print "[+] VICTIM MAC {}".format(self.targetMAC)		
		print "[+] GATEWAY IP {}".format(self.gatewayIP)
		print "[+] GATEWAY MAC {}".format(self.gatewayMAC)



	def setup(self, conf):
  		print ("lol")


if __name__ == "__main__":
	if os.geteuid() != 0:
		sys.exit("[-] Only for roots kido! ")
	swrt = SWRT()
	if (swrt.args.conf != None):
		config = DNSConf.DNSConf(swrt.args.interface, swrt.args.conf)
	try:
		os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports {}".format(swrt.args.port))
		swrt.setup(config)
		'''
		while True:
			sleep(10000)
		'''
	except KeyboardInterrupt:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		os.system('iptables -t nat -F')
		exit(0)
	except Exception as e:
		exc_type, exc_value, exc_traceback = sys.exc_info()
		print "*** print_tb:"
		traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
		print "*** print_exception:"
		traceback.print_exception(exc_type, exc_value, exc_traceback,
	                              limit=2, file=sys.stdout)
		print "*** print_exc:"
		traceback.print_exc()
		print "*** format_exc, first and last line:"
		formatted_lines = traceback.format_exc().splitlines()
		print formatted_lines[0]
		print formatted_lines[-1]
		print "*** format_exception:"
		print repr(traceback.format_exception(exc_type, exc_value,
	                                          exc_traceback))
		print "*** extract_tb:"
		print repr(traceback.extract_tb(exc_traceback))
		print "*** format_tb:"
		print repr(traceback.format_tb(exc_traceback))
		print "*** tb_lineno:", exc_traceback.tb_lineno		
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		os.system('iptables -t nat -F')
		exit(0)