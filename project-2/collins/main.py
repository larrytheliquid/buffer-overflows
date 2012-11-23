#!/usr/bin/python
# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id: split.py 17 2003-10-27 17:36:57Z jkohen $
#
# Pcap dump splitter.
#
# This tools splits pcap capture files into smaller ones, one for each
# different TCP/IP connection found in the original.
#
# Authors:
#  Alejandro D. Weil <aweil@coresecurity.com>
#  Javier Kohen <jkohen@coresecurity.com>
#
# Reference for:
#  pcapy: open_offline, pcapdumper.
#  ImpactDecoder.

import sys
import string
from exceptions import Exception
from threading import Thread

import pcapy
from pcapy import open_offline
import impacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

class Connection:
    """This class can be used as a key in a dictionary to select a connection
    given a pair of peers. Two connections are considered the same if both
    peers are equal, despite the order in which they were passed to the
    class constructor.
    """

    def __init__(self, p1, p2):
        """This constructor takes two tuples, one for each peer. The first
        element in each tuple is the IP address as a string, and the
        second is the port as an integer.
        """

        self.p1 = p1
        self.p2 = p2

    def getFilename(self):
        """Utility function that returns a filename composed by the IP
        addresses and ports of both peers.
        """
        return '%s.%d-%s.%d.pcap'%(self.p1[0],self.p1[1],self.p2[0],self.p2[1])

    def __cmp__(self, other):
        if ((self.p1 == other.p1 and self.p2 == other.p2)
            or (self.p1 == other.p2 and self.p2 == other.p1)):
            return 0
        else:
            return -1

    def __hash__(self):
        return (hash(self.p1[0]) ^ hash(self.p1[1])
                ^ hash(self.p2[0]) ^ hash(self.p2[1]))

# Copied from C pcap tutorial. These must be def'd by Impacket
# somewhere ...
TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20
TH_ECE = 0x40
TH_CWR = 0x80

class Decoder:
    def __init__(self, pcapObj):
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcapObj
        self.handshakes = {}
        self.connections = []

    def start(self):
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        self.pcap.loop(0, self.packetHandler)

    def packetHandler(self, hdr, data):
        p = self.decoder.decode(data)
        ip = p.child()
        tcp = ip.child()
        src = (ip.get_ip_src(), tcp.get_th_sport() )
        dst = (ip.get_ip_dst(), tcp.get_th_dport() )

        # Handshake 1
        if tcp.get_th_flags() == TH_SYN:
            #print "1"
            client_server = (src,dst)
            self.handshakes[client_server] = { "client_seq" : tcp.get_th_seq() }
        # Handshake 2
        #
        # XXX: For the purposes of defining a "server", replying with
        # SYN-ACK may be sufficient.  In particular, a port scan would
        # identify servers that I don't identify, since I'm requiring
        # the handshake to complete.
        elif tcp.get_th_flags() == TH_SYN | TH_ACK:
            #print "2?"
            client_server = (dst,src)
            if client_server in self.handshakes:
                #print "2??"
                hs = self.handshakes[client_server]
                if hs.get("client_seq",None) == tcp.get_th_ack() - 1:
                    hs["server_seq"] = tcp.get_th_seq()
                else:
                    #print "2 fail: expecting %i, got $i" % (hs.get("client_seq",None),tcp.get_th_ack())
                    # Could be more paranoid here: got an unexpected handshake 2.
                    pass
        # Handshake 3
        elif tcp.get_th_flags() == TH_ACK:
            #print "3"
            client_server = (src,dst)
            if client_server in self.handshakes:
                hs = self.handshakes[client_server]
                if hs.get("client_seq",None) == tcp.get_th_seq() - 1 and \
                   hs.get("server_seq",None) == tcp.get_th_ack() - 1:
                    self.handshakes.pop(client_server)
                    self.connections.append(client_server)

    def packetHandler_(self, hdr, data):
        """Handles an incoming pcap packet. This method only knows how
        to recognize TCP/IP connections.
        Be sure that only TCP packets are passed onto this handler (or
        fix the code to ignore the others).

        Setting r"ip proto \tcp" as part of the pcap filter expression
        suffices, and there shouldn't be any problem combining that with
        other expressions.
        """

        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        p = self.decoder.decode(data)
        ip = p.child()
        tcp = ip.child()

        # Build a distinctive key for this pair of peers.
        src = (ip.get_ip_src(), tcp.get_th_sport() )
        dst = (ip.get_ip_dst(), tcp.get_th_dport() )
        con = Connection(src,dst)

        # If there isn't an entry associated yetwith this connection,
        # open a new pcapdumper and create an association.
        if not self.connections.has_key(con):
            fn = con.getFilename()
            print "Found a new connection, storing into:", fn
            try:
                dumper = self.pcap.dump_open(fn)
            except pcapy.PcapError, e:
                print "Can't write packet to:", fn
                return
            self.connections[con] = dumper

        # Write the packet to the corresponding file.
        self.connections[con].dump(hdr, data)



def main(filename):
    # Open file
    p = open_offline(filename)

    # At the moment the callback only accepts TCP/IP packets.
    p.setfilter(r'ip proto \tcp')

    #print "Reading from %s: linktype=%d" % (filename, p.datalink())

    # Start decoding process.
    global d
    d = Decoder(p)
    d.start()

    servers = [ s for (_,s) in d.connections ]
    server_stats = {}
    for s in servers:
        server_stats[s] = server_stats.get(s,0) + 1
    sorted_server_stats = sorted(server_stats.iteritems(),
                                 key=lambda (_,c): c, reverse=True)
    print "%-14s %-5s %s" % ("Server", "Port", "Connections")
    print "%s %s %s"      % ("="*14, "="*5, "="*len("Connections"))
    print
    for ((s,p),c) in sorted_server_stats:
        print "%-14s %-5i %i" % (s,p,c)


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s <filename>" % sys.argv[0]
        sys.exit(1)

    main(sys.argv[1])
