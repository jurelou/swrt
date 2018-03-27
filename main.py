#!/usr/bin/python2.7 
 
import argparse
import os
import threading, time
import sys
import ARPPoisoner
import DNSSniff
 
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
 
 
 
def has_live_threads(threads):
  return True in [t.isAlive() for t in threads]

def main():
  SWRT().parseArgs()
  SWRT().printArgs()
 
  threads = []
  thread = DNSSniff.DNSSniffer(SWRT.args.target, SWRT.args.interface)
  thread.start()
  threads.append(thread)
 
  while has_live_threads(threads):
    try:
      [t.join(1) for t in threads
      if t is not None and t.isAlive()]
    except KeyboardInterrupt:
      for t in threads:
        t.stop()
        t.kill_received = True
  print " -- exited"      
 
if __name__ == '__main__':
  if os.getuid()!=0:
    print("Need root privileges to run properly; Re-run as sudo...")
    sys.exit()
  main()