require 'rubygems'
require 'bundler/setup'
require 'packetfu'
require 'pry'
require 'pp'

class Parser
  attr_accessor :packets
  def initialize(filename)
    self.packets = PacketFu::PcapFile.read_packets(filename)
  end

  def tcp_packets
    packets.select(&:is_tcp?)
  end

  def server_packets
    tcp_packets.select do |packet|
      packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 1
    end
  end

  def syn_packets
    tcp_packets.select do |packet|
      packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 0
    end
  end

  def servers_and_ports
    result = {}
    server_packets.each do |packet|
      key = packet.ip_saddr
      if ports = result[key]
        ports << packet.tcp_sport
      else
        ports = Set.new
        ports << packet.tcp_sport
        result[key] = ports
      end
    end
    result
  end

  def servers
    servers_and_ports.keys
  end

  def servers_and_traffic
    result = {}
    servers.each do |server|
      result[server] = [0, 0]
    end

    tcp_packets.each do |packet|
      key = packet.ip_saddr
      if result.include?(key)
        result[key] = [result[key].first.succ, (result[key].last + packet.payload.size)]
      end
    end
    result
  end

  def scanners_and_ports
    result = {}
    syn_packets.each do |packet|
      key = [packet.ip_saddr, packet.ip_daddr]
      if ports = result[key]
        ports << packet.tcp_dport
      else
        ports = Set.new
        ports << packet.tcp_dport
        result[key] = ports
      end
    end
    result.keys.each do |key|
      result.delete key if result[key].size < 100
    end
    result
  end

  def self.shell
    parser = self.new ARGV[0]
    binding.pry
  end

  def self.print
    parser = self.new ARGV[0]

    puts "Part 1: Servers and ports"
    parser.servers_and_ports.each do |k, v|
      puts "#{k}:#{v.to_a.join(',')}"
    end
    puts

    puts "Part 2: Servers, connections, and traffic"
    parser.servers_and_traffic.each do |k, v|
      puts "#{k} - #{v.first} (connections) #{v.last} (bytes)"
    end
    puts

    puts "Part 3: Port scanners"
    parser.scanners_and_ports.each do |k, v|
      puts "#{k.first} -> #{k.last} / #{v.size} ports"
    end
    puts
  end
end

Parser.print



