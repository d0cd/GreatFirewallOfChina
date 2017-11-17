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

triggerfetch = "GET / HTTP/1.0\nHost: www.google.com\n\n"

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
        return "NEED TO IMPLEMENT"
        
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
        response = self.get_pkt()
        if response == None:
            return "DEAD"
        # Send TCP ACK
        y = response[TCP].seq
        self.send_pkt(flags=0x10, sport=srcp, seq=x+1, ack=y+1)
        # Send payload
        self.send_pkt(flags=0x10, sport=srcp, seq=x+1, ack=y+1, payload=triggerfetch)
        # Wait for response
        loop = True
        while loop:
            response = self.get_pkt()
            if (response[TCP].flags == 0x12):
                self.send_pkt(flags=0x10, sport=srcp, seq=x+1, ack=y+1, payload=triggerfetch)
            else:
                loop = False
        if isRST(response):
            return "FIREWALL"
        else:
            print(response[TCP].flags == 0x12)
            return "LIVE" #Do we need to check the response packet for a valid response?

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
        self.dst = target
        x = random.randint(1, 31313131)
        self.send_pkt(flags=0x02, seq=x)
        loop = True
        response = self.get_pkt()
        if response == None:
            return  ([None], [False])
        y = response[TCP].seq
        self.send_pkt(flags=0x10, seq=x+1, ack=y)
        ttl = 1
        RstArray = []
        IPArray = []
        i =0
        while True:
            self.send_pkt(payload=triggerfetch, ttl=ttl)
            self.send_pkt(payload=triggerfetch, ttl=ttl)
            self.send_pkt(payload=triggerfetch, ttl=ttl)
            time.sleep(5)
            response1 = self.get_pkt()
            response2 = self.get_pkt()
            response3 = self.get_pkt()
            responseLogger(response1)
            responseLogger(response2)
            responseLogger(response3)
            if ((response1 != None and isRST(response1)) or (response2 != None and isRST(response2)) or (response3 != None and isRST(response3))):
                RstArray.append(True)
            if ((response1 != None and isICMP(response1)) or (response2 != None and isICMP(response2)) or (response3 != None and isICMP(response3))):
                if(response1 != None and isTimeExceeded(response1)):
                    RstArray.append(False)
                    IPArray.append(response1[IP].src)
                elif (response2 != None and isTimeExceeded(response2)):
                    RstArray.append(False)
                    IPArray.append(response2[IP].src)
                elif (response2 != None and isTimeExceeded(response3)):
                    RstArray.append(False)
                    IPArray.append(response3[IP].src)
                else:
                    RstArray.append(False)
            arrayLogger(IPArray)
            ttl += 1
            i += 1
            if ttl > hops:
                break
            self.packetQueue = Queue.Queue(100000)
        return (IPArray, RstArray)

def responseLogger(response):
    if (response != None):
        logging.debug(response[0].show())

def arrayLogger(array):
    for i in array:
        logging.debug("array is :")
        logging.debug(i)