#!/usr/bin/python

# Based on impacket/examples/split.py.

import local

import sys
from exceptions import Exception

import pcapy
from pcapy import open_offline
import impacket
from impacket.ImpactDecoder import EthDecoder


# TCP flag bits.
#
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


class Decoder(object):
    def __init__(self, pcap):
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = pcap.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcap

    def start(self):
        self.pcap.loop(0, self.packetHandler)

    def packetHandler(self, hdr, data):
        p = self.decoder.decode(data)
        ip = p.child()
        tcp = ip.child()
        src = (ip.get_ip_src(), tcp.get_th_sport() )
        dst = (ip.get_ip_dst(), tcp.get_th_dport() )
        return (p,ip,tcp,src,dst)

    def report(self):
        raise Exception("Not implemented")


class Part1Decoder(Decoder):
    def __init__(self, pcap):
        Decoder.__init__(self,pcap)
        self.syn_acks = set()

    def packetHandler(self, hdr, data):
        (p,ip,tcp,src,dst) = Decoder.packetHandler(self,hdr,data)

        # Handshake 2
        #
        # Define a server as anything that responds to connection
        # requests, i.e. that sends SYN-ACK packets. Not actually
        # checking for the initiating SYN, but have that code in
        # "Handshake 1" part.

        # XXX: the pcap prefilter makes the explicit check redundant.
        if tcp.get_th_flags() == TH_SYN | TH_ACK:
            self.syn_acks.add(src)

    def report(self):
        for (s,p) in sorted(self.syn_acks, reverse=True):
            print s, p

    def report_fancy(self):
        print "%-14s %-5s" % ("Server", "Port")
        print "%s %s"      % ("="*14, "="*5)
        print
        for (s,p) in sorted(self.syn_acks, reverse=True):
            print "%-14s %-5i" % (s,p)


class Part2Decoder(Decoder):
    def __init__(self, pcap):
        Decoder.__init__(self,pcap)
        self.handshakes = {}
        self.connections = {}
        self.served = {}

    def packetHandler(self, hdr, data):
        (p,ip,tcp,src,dst) = Decoder.packetHandler(self,hdr,data)
        # Handshake 1
        if tcp.get_th_flags() == TH_SYN:
            client_server = (src,dst)
            self.handshakes[client_server] = { "client_seq" : tcp.get_th_seq() }
        # Handshake 2
        elif tcp.get_th_flags() == TH_SYN | TH_ACK:
            client_server = (dst,src)
            if client_server in self.handshakes:
                hs = self.handshakes[client_server]
                if hs.get("client_seq",None) == tcp.get_th_ack() - 1:
                    hs["server_seq"] = tcp.get_th_seq()
                else:
                    #print "2 fail: expecting %i, got $i" % (hs.get("client_seq",None),tcp.get_th_ack())
                    pass
        # Handshake 3
        elif tcp.get_th_flags() == TH_ACK:
            client_server = (src,dst)
            if client_server in self.handshakes:
                hs = self.handshakes[client_server]
                if hs.get("client_seq",None) == tcp.get_th_seq() - 1 and \
                   hs.get("server_seq",None) == tcp.get_th_ack() - 1:
                    self.handshakes.pop(client_server)
                    self.connections[client_server] = \
                        self.connections.get(client_server,0) + 1
        # Data served?
        else:
            client_server = (dst,src)
            if client_server in self.connections:
                self.served[client_server] = self.served.get(client_server,0) \
                                           + tcp.get_size()

    def report(self):
        # connections :: (client,server) -> number of connections
        # sent        :: (client,server) -> bytes sent

        # output format: server_ip port connections bytes
        servers = {}
        # Don't distinguish clients
        for ((client,server),connections) in self.connections.iteritems():
            d = servers.get(server,{})
            d['connections'] = d.get('connections',0) + connections
            servers[server] = d

        for ((client,server),bytes) in self.served.iteritems():
            d = servers.get(server,{})            
            d['bytes'] = d.get('bytes',0) + bytes
            servers[server] = d

        for ((s,ip),d) in sorted(servers.iteritems(), key=lambda (s,d): s):
            print s, ip, d['connections'], d.get('bytes',0)


class Part3Decoder(Decoder):
    def __init__(self, pcap):
        Decoder.__init__(self,pcap)
        self.sinners = {}

    def packetHandler(self, hdr, data):
        (p,ip,tcp,src,dst) = Decoder.packetHandler(self,hdr,data)
        if tcp.get_th_flags() == TH_SYN:
            (attacker_ip,_) = src
            (victim_ip,victim_port) = dst
            self.sinners.setdefault(attacker_ip,{}) \
                .setdefault(victim_ip,set()) \
                .add(victim_port)

    def report(self):
        # sinners :: attacker_ip -> victim_ip -> ports_syn ed

        # output format: attacker_ip server_ip number_of_ports_scanned
        attacks = []
        for (attacker,victims) in self.sinners.iteritems():
            for (victim,ports) in victims.iteritems():
                attacks.append((attacker,victim,len(ports)))

        # Sort first on number of SYNs
        for (a,v,n) in sorted(attacks, key=lambda (a,v,n): (n,a,v), reverse=True):
            if n >= 0: # 100:
                print a,v,n

def main1(filename):
    p = open_offline(filename)
    # Restrict to tcp packets with only syn and ack set.
    p.setfilter(r'tcp[tcpflags] == (tcp-syn | tcp-ack)')
    d = Part1Decoder(p)
    d.start()
    d.report()

def main2(filename):
    p = open_offline(filename)
    # Restrict to tcp.
    #
    # XXX: could gain speed by doing two phases: one to find servers
    # which only looks at handshake packets, and one which counts
    # traffic, but restricted to packets for known streams.
    p.setfilter(r'tcp')
    d = Part2Decoder(p)
    d.start()
    d.report()

def main3(filename):
    p = open_offline(filename)
    # Restrict to tcp packets with only syn set.
    p.setfilter(r'tcp[tcpflags] == tcp-syn')
    d = Part3Decoder(p)
    d.start()
    d.report()

if __name__ == '__main__':
    if len(sys.argv) != 1+2:
        print "Usage: %s [1|2|3] <filename>" % sys.argv[0]
        sys.exit(1)

    mains = [main1,main2,main3]
    mains[int(sys.argv[1])-1](sys.argv[2])
