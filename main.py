#!/usr/bin/python2.7
import argparse

class SWRT(object):
	args = 0
	def parseArgs(self):
		parser = argparse.ArgumentParser()
		parser.add_argument("-d", "--debug", help="increase output verbosity", action="store_true")
		parser.add_argument('-i', action='store', dest='interface', help='Store the interface', required=True)
		parser.add_argument('-t', action='store', dest='target', help='Store a target IP address', required=True)
		SWRT.args = parser.parse_args()

	def printArgs(self):
		if SWRT.args.debug:
			print(" -- debug mode on")
		else:
			print(" -- debug mode off")
			print(" -- interface:" +  SWRT.args.interface)
			print(" -- target:" +  SWRT.args.target)		

if __name__ == '__main__':
    SWRT().parseArgs()
    SWRT().printArgs()