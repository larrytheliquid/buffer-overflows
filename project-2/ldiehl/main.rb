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
    @tcp_packets ||= packets.select(&:is_tcp?)
  end

  def server_packets
    @server_packets ||= tcp_packets.select do |packet|
      packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 1
    end
  end

  def syn_packets
    @syn_packets ||= tcp_packets.select do |packet|
      packet.tcp_flags.syn == 1 && packet.tcp_flags.ack == 0
    end
  end

  def servers
    result = Set.new
    server_packets.each do |packet|
      result << [packet.ip_saddr, packet.tcp_sport]
    end
    result
  end

  def servers_and_traffic
    result = {}
    servers.each do |server|
      result[server] = [0, 0]
    end

    tcp_packets.each do |packet|
      key = [packet.ip_daddr, packet.tcp_dport]
      if result.include?(key)
        if packet.tcp_flags.syn == 0 && packet.tcp_flags.ack == 1
          result[key][0] = result[key][0].succ
        end
      end

      key = [packet.ip_saddr, packet.tcp_sport]
      if result.include?(key)
        result[key][1] = result[key][1] + packet.payload.size
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
    parser.servers.each do |server_ip, port|
      puts [server_ip, port].join(" ")
    end
    puts

    puts "Part 2: Servers, connections, and traffic"
    parser.servers_and_traffic.each do |(server_ip, port), (conns, bytes)|
      puts [server_ip, port, conns, bytes].join(" ")
    end
    puts

    puts "Part 3: Port scanners"
    parser.scanners_and_ports.each do |(attacker_ip, server_ip), ports|
      puts [attacker_ip, server_ip, ports.size].join(" ")
    end
    puts
  end
end

Parser.print



