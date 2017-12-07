#!/usr/bin/env python

import time
import threading
from scapy.all import *
import sys
import socket
import json
import Queue
import interfaces
import logging

maxhop = 25

# A request that will trigger the great firewall but will NOT cause
# the web server to process the connection.  You probably want it here

triggerfetch = "GET /search?Falun+gong HTTP/1.0\nHost: www.google.com\n\n"
# A couple useful functions that take scapy packets
def isRST(p):
    return (TCP in p) and (p[IP][TCP].flags & 0x4 != 0)

def isICMP(p):
    return ICMP in p

def isTimeExceeded(p):
    return ICMP in p and p[IP][ICMP].type == 11

# A general python object to handle a lot of this stuff...
#
# Use this to implement the actual functions you need.
class PacketUtils:
    def __init__(self, dst=None):
        # Get one's SRC IP & interface
        i = interfaces.interfaces()
        self.src = i[1][0]
        self.iface = i[0]
        self.netmask = i[1][1]
        self.enet = i[2]
        self.dst = dst
        sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" %
                         (self.src, self.iface, self.netmask, self.enet))
        # A queue where received packets go.  If it is full
        # packets are dropped.
        self.packetQueue = Queue.Queue(100000)
        self.dropCount = 0
        self.idcount = 0

        self.ethrdst = ""

        # Get the destination ethernet address with an ARP
        self.arp()
        
        # You can add other stuff in here to, e.g. keep track of
        # outstanding ports, etc.
        
        # Start the packet sniffer
        t = threading.Thread(target=self.run_sniffer)
        t.daemon = True
        t.start()
        time.sleep(.1)

    # generates an ARP request
    def arp(self):
        e = Ether(dst="ff:ff:ff:ff:ff:ff",
                  type=0x0806)
        gateway = ""
        srcs = self.src.split('.')
        netmask = self.netmask.split('.')
        for x in range(4):
            nm = int(netmask[x])
            addr = int(srcs[x])
            if x == 3:
                gateway += "%i" % ((addr & nm) + 1)
            else:
                gateway += ("%i" % (addr & nm)) + "."
        sys.stderr.write("Gateway %s\n" % gateway)
        a = ARP(hwsrc=self.enet,
                pdst=gateway)
        p = srp1([e/a], iface=self.iface, verbose=0)
        self.etherdst = p[Ether].src
        sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))


    # A function to send an individual packet.
    def send_pkt(self, payload=None, ttl=32, flags="",
                 seq=None, ack=None,
                 sport=None, dport=80,ipid=None,
                 dip=None,debug=False):
        if sport == None:
            sport = random.randint(1024, 32000)
        if seq == None:
            seq = random.randint(1, 31313131)
        if ack == None:
            ack = random.randint(1, 31313131)
        if ipid == None:
            ipid = self.idcount
            self.idcount += 1
        t = TCP(sport=sport, dport=dport,
                flags=flags, seq=seq, ack=ack)
        ip = IP(src=self.src,
                dst=self.dst,
                id=ipid,
                ttl=ttl)
        p = ip/t
        if payload:
            p = ip/t/payload
        else:
            pass
        e = Ether(dst=self.etherdst,
                  type=0x0800)
        # Have to send as Ethernet to avoid interface issues
        sendp([e/p], verbose=1, iface=self.iface)
        # Limit to 20 PPS.
        time.sleep(.05)
        # And return the packet for reference
        return p


    # Has an automatic 5 second timeout.
    def get_pkt(self, timeout=5):
        try:
            return self.packetQueue.get(True, timeout)
        except Queue.Empty:
            return None

    # The function that actually does the sniffing
    def sniffer(self, packet):
        try:
            # non-blocking: if it fails, it fails
            self.packetQueue.put(packet, False)
        except Queue.Full:
            if self.dropCount % 1000 == 0:
                sys.stderr.write("*")
                sys.stderr.flush()
            self.dropCount += 1

    def run_sniffer(self):
        sys.stderr.write("Sniffer started\n")
        rule = "src net %s or icmp" % self.dst
        sys.stderr.write("Sniffer rule \"%s\"\n" % rule)
        sniff(prn=self.sniffer,
              filter=rule,
              iface=self.iface,
              store=0)

    # Sends the message to the target in such a way
    # that the target receives the msg without
    # interference by the Great Firewall.
    #
    # ttl is a ttl which triggers the Great Firewall but is before the
    # server itself (from a previous traceroute incantation
    def evade(self, target, msg, ttl):
        srcp = random.randint(2000, 30000)
        x = random.randint(1, 31313131)
        self.dst = target
        # Send TCP SYN
        self.send_pkt(flags=0x02, sport=srcp, seq=x)
        # Wait for response
        response = self.get_pkt()
        while response == None or TCP not in response or response[TCP].flags != 0x12:
            self.send_pkt(flags=0x02, sport=srcp, seq=x)
            response = self.get_pkt()
        y = response[TCP].seq
        #Send ACK back
        self.send_pkt(flags=0x10, sport=srcp, seq=x+1, ack=y+1)
        #Send data
        split_msg = list(bytearray(msg))
        print(len(split_msg))
        for b in msg:
            self.send_pkt(flags=0x10, ttl=ttl, sport=srcp, seq=x+1, ack=y+1, payload=b)
            self.send_pkt(flags=0x10, sport=srcp, seq=x+1, ack=y+1, payload=b)
            x += 1
        time.sleep(10)
        payloads = []
        while not self.packetQueue.empty():
            p = self.get_pkt()
            if 'Raw' in p:
                payloads.append(p['Raw'].load)
                y = response[TCP].seq
        #End the connection        
        self.send_pkt(flags=0x04, sport=srcp, seq=x+1, ack=y+1)
        return payloads    
        
    # Returns "DEAD" if server isn't alive,
    # "LIVE" if teh server is alive,
    # "FIREWALL" if it is behind the Great Firewall
    def ping(self, target):
        srcp = random.randint(2000, 30000)
        x = random.randint(1, 31313131)
        self.dst = target
        # Send TCP SYN
        self.send_pkt(flags=0x02, sport=srcp, seq=x)
        # Wait for response
        response = self.get_pkt(10)
        if response == None:
            return "DEAD"
        # Send TCP ACK
        y = response[TCP].seq
        self.send_pkt(flags=0x10, sport=srcp, seq=x+1, ack=y+1)
        # Send payload
        self.send_pkt(flags=0x10, sport=srcp, seq=x+1, ack=y+1, payload=triggerfetch)
        # Wait for response
        time.sleep(5)
        packet_count, rst_count = 0, 0
        while not self.packetQueue.empty():
            p = self.get_pkt()
            if isRST(p):
                rst_count += 1
            packet_count += 1
        if rst_count > 0:
            return "FIREWALL"
        elif packet_count > 0:
            return "LIVE"
        else:
            return "NO RESPONSE RECIEVED"
    


    # Format is
    # ([], [])
    # The first list is the list of IPs that have a hop
    # or none if none
    # The second list is T/F 
    # if there is a RST back for that particular request

    #start with ttl 1. increment till hops
    # USE TCP Handshake, if any of the responses are an RST or timeExpired second array is true
    # Empty queue after every hop

    def traceroute(self, target, hops):
        test_ttl = 1
      
        self.dst = target
        IPArray, RSTArray = [None] * hops, [False] * hops
        
        while test_ttl <= hops:
            # Empty packetQueue
            srcp = random.randint(2000, 30000)
            x = random.randint(1, 31313131)    
            self.send_pkt(flags=0x02, sport=srcp, seq=x)
            # Wait for response
            response = self.get_pkt()
            while response == None or TCP not in response or response[TCP].flags != 0x12:
                self.send_pkt(flags=0x02, sport=srcp, seq=x)
                response = self.get_pkt(timeout=3)
            # Send TCP ACK
            y = response[TCP].seq
            self.send_pkt(flags=0x10, sport=srcp, seq=x+1, ack=y+1)
            # Send payload 3 times
            self.send_pkt(flags=0x10, ttl=test_ttl, sport=srcp, seq=x+1, ack=y+1, payload=triggerfetch)
            self.send_pkt(flags=0x10, ttl=test_ttl, sport=srcp, seq=x+1, ack=y+1, payload=triggerfetch)
            self.send_pkt(flags=0x10, ttl=test_ttl, sport=srcp, seq=x+1, ack=y+1, payload=triggerfetch)
            # Check for RST or ICMP
            while not self.packetQueue.empty():
                p = self.get_pkt()
                if isTimeExceeded(p): 
                    IPArray[test_ttl - 1] = p[IP].src
                    #RSTArray.append(False)
                if isRST(p):
                    #IPArray.append(p[IP].src)
                    RSTArray[test_ttl - 1] = True
            test_ttl += 1
            while not self.packetQueue.empty():
                p = self.get_pkt()
        return (IPArray, RSTArray)


def responseLogger(response):
    if (response != None):
        logging.debug(response[0].show())
    else: logging.debug('None')

def arrayLogger(array):
    logging.debug("array is: ")
    for i in array:
        if i== None:
            logging.debug("None")
        else:
            logging.debug(i)