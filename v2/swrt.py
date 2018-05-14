#!/usr/bin/env python2.7
import os, sys
import DNSConf
import argparse

BLUE = '\033[94m'
END = '\033[0m'
port = 8080
class SWRT(object):
  args = 0
  def parseArgs(self):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="increase output verbosity", action="store_true", required=False)
    parser.add_argument('-i', action='store', default="ens33", dest='interface', help='Store the interface', required=False)
    parser.add_argument('-t', action='store', dest='target', help='Store a target IP address', required=True)
    parser.add_argument('-r', action='store', default="192.168.1.1", dest='gateway', help='Store the gateway IP address', required=False)
    parser.add_argument('-c', action='store', dest='conf', default='./conf.json', help='Store path/to/conf.json', required=False)
    parser.add_argument('-p', action='store', default="8080", dest='port', help='Store the port', required=False)
    SWRT.args = parser.parse_args()
 
  def printArgs(self):
    if SWRT.args.debug:
      print (BLUE + " -- debug mode on")
    else:
      print  (BLUE + "-- debug mode off")
      print (" -- interface:" +  SWRT.args.interface)
      print (" -- target:" +  SWRT.args.target)
      print (" -- gateway:" +  SWRT.args.gateway + END)

if __name__ == "__main__":
	if os.geteuid() != 0:
		sys.exit("[-] Only for roots kido! ")
	SWRT().parseArgs()
	SWRT().printArgs()
	if (SWRT.args.conf != None):
		conf = DNSConf.DNSConf(SWRT.args.interface, SWRT.args.conf)
	try:
		print ('\033[92m[+]\tStarting dns\033[0m')
		os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports {}".format(SWRT.args.port))
	except KeyboardInterrupt:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		os.system('iptables -t nat -F')
		exit(0)
	except Exception as e:
		print ('\033[91m[-]\tOoooops{}\033[0m'.format(e))
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		os.system('iptables -t nat -F')
		exit(0)