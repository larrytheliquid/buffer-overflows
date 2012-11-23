require 'rubygems'
require 'bundler/setup'
require 'packetfu'
require 'pp'

Packets = PacketFu::PcapFile.read_packets ARGV[0]; Packets.first

irb



