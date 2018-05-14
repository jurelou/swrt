#!/usr/bin/env python

import json, sys
from scapy.all import *

class DNSConf:
    def __init__(self, interface, config='conf.json'):
        self.__configFile = config
        fd = open(self.__configFile)
        self.conf = json.load(fd)
        if ('DNSEntries' in self.conf):
            for item in self.conf['DNSEntries']:
                if ('ip' in item):
                    if (item['ip'] == 'mine'):
                        item['ip'] = get_if_addr(interface)
                else:
                    print('missing field ip in DNSEntries element')
                    exit(1)
                if ('domains' not in item):
                    print('missing field domain in DNSEntries element')
                    exit(1)

    def getDomains(self):
        res = []
        for entry in self.conf['DNSEntries']:
            res += entry['domains']
        return (res)

    def getIPFromDomain(self, domain):
        for entry in self.conf['DNSEntries']:
            if domain in entry['domains']:
                return (entry['ip']);
        return (None);

    def printConfig(self):
        for entry in self.conf['DNSEntries']:
            print('domains : ' + ', '.join(entry['domains']))
            print('\t are binded to : ' + entry['ip'])

def main():
    if (len(sys.argv) > 2):
        obj = DNSConf(sys.argv[1], sys.argv[2])
    elif (len(sys.argv) == 2):
        obj = DNSConf(sys.argv[1])
    else:
        print("usage: " + sys.argv[0] + " interface [path/to/conf.json]")
        exit(0)
    obj.printConfig()
            

if __name__ == "__main__":
    main()
