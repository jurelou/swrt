#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, time, threading, abc

class thread_sample(threading.Thread):
    def __init__(self, name):
        threading.Thread.__init__(self)
        self.name = name
        self.kill_received = False
 
    def run(self):
        while not self.kill_received:
            # your code
            print self.name, "is active"
            time.sleep(1)
    def stop(self):
        print "je me retire"        

def has_live_threads(threads):
    return True in [t.isAlive() for t in threads]

def main():
    threads = []
    thread = thread_sample("thread1")
    thread.start()
    threads.append(thread)

    thread = thread_sample("thread2")
    thread.start()
    threads.append(thread)


    while has_live_threads(threads):
        try:
            [t.join(1) for t in threads
             if t is not None and t.isAlive()]
        except KeyboardInterrupt:
            # Ctrl-C handling and send kill to threads
            print "Sending kill to threads..."
            for t in threads:
                t.stop()
                t.kill_received = True

    print "Exited"

if __name__ == '__main__':
   main()