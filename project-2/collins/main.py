#!/usr/bin/python

# Based on impacket/examples/split.py.

import sys
from exceptions import Exception

import pcapy
from pcapy import open_offline
import impacket
from impacket.ImpactDecoder import EthDecoder


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
    def __init__(self, pcap):
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = pcap.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcap
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


def main(filename):
    p = open_offline(filename)
    p.setfilter(r'ip proto \tcp')
    global d
    d = Decoder(p)
    d.start()

    # Report server stats
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


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s <filename>" % sys.argv[0]
        sys.exit(1)

    main(sys.argv[1])
