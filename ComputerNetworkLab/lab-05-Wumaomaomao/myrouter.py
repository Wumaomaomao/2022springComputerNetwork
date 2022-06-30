#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
import threading
import queue
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class forwarding_table(object):
    def __init__(self, forwarding_table, net):
        self.forwarding_table = forwarding_table
        my_interface = net.interfaces()
        # fill forwardingtable with the interfaces of router
        for intf in my_interface:
            IPv4addr = intf.ipaddr
            mask = intf.netmask
            #compute the IPv4address prefix
            prefix = IPv4Address(int(IPv4addr) & int(mask))
            # print(f"{prefix}, {type(prefix)}")
            forwarding_table.append([format(prefix), format(intf.netmask),'0.0.0.0',intf.name])
            # log_info(f"ipaddr:{intf.ipaddr}/{type(format(intf.ipaddr)},netmask:{intf.netmask}/{type(intf.netmask)},next hop:0.0.0.0,intfname:{intf.name}/{type(intf.name)})")
        # fill forwardingtable with the forwardingtable file
        file = open('forwarding_table.txt','r')
        text = file.readlines()
        for entry in text:
            cells = entry.split()
            ipaddr = cells[0]
            netmask = cells[1]
            nexthop = cells[2]
            name = cells[3]
            forwarding_table.append([ipaddr, netmask, nexthop, name])
            #log_info(f"ipaddr:{ipaddr},netmask:{netmask},next hop:{nexthop},intfname:{name}")
        for entry in forwarding_table:
            log_info(f"ipaddr:{entry[0]}/{type(entry[0])},netmask:{entry[1]}/{type(entry[1])},next hop:{entry[2]}/{type(entry[2])},intfname:{entry[3]}/{type(entry[3])})")
    def lookup(self,ipaddr):
        prefixlen = 0
        nexthop = None
        forward_intf = None
        destaddr = IPv4Address(ipaddr)
        for entry in self.forwarding_table:
            #log_info(f"{entry[0]+ '/' + entry[1]}")
            prefixnet =IPv4Network(format(entry[0]+ '/' + entry[1]),strict=False)
            if destaddr in prefixnet:
                #log_info(f"{destaddr},{entry}")
                if prefixnet.prefixlen > prefixlen:
                    #update for the longer prefixlen
                    prefixlen = prefixnet.prefixlen
                    nexthop = entry[2]
                    forward_intf = entry[3]
        #log_info(f"prefixlen:{prefixlen},nexthop:{nexthop}")
        return prefixlen, nexthop, forward_intf

class Arptable(object):
    def __init__(self, table):
        self.table = table
    def timeout(self):
        delete_key =[];
        timestamp = time.time()
        for key in self.table:
            if (self.table[key][1] + 20 <= timestamp):
                delete_key.append(key);
        for key in delete_key:
            self.table.pop(key)

    def update_Arptable(self, ipaddr, macaddr):
        self.timeout()
        timestamp = time.time()
        self.table[ipaddr] = [macaddr, timestamp]
        for key in self.table:
            log_info(f"ipaddr:{key} macaddr:{self.table[key][0]} timestamp:{self.table[key][1]}")
    
    def lookup(self,ipaddr):
        Ipaddr = IPv4Address(ipaddr)
        if Ipaddr in self.table:
            return self.table[Ipaddr][0]
        else:
            return None

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.wait_packet = dict()
        self.arptable = Arptable(dict())
        self.forwarding_table = forwarding_table(list(),self.net)
        self.wait_queue = queue.Queue()
        # other initialization stuff here

    def create_icmp_echo_reply(self, request_icmp_header, request_ip_header):
        # icmp header
        reply_icmp_header = ICMP()
        # log_info(f"{reply_icmp_header}")
        # log_info(f"{request_icmp_header.icmpdata.data}")
        reply_icmp_header.icmptype = ICMPType.EchoReply
        reply_icmp_header.icmpdata.sequence = request_icmp_header.icmpdata.sequence
        reply_icmp_header.icmpdata.identifier = request_icmp_header.icmpdata.identifier
        reply_icmp_header.icmpdata.data = request_icmp_header.icmpdata.data
        # log_info(f"{reply_icmp_header.icmpdata.data}")
        # ipv4 header
        reply_ip_header = IPv4()
        reply_ip_header.src = request_ip_header.dst
        reply_ip_header.dst = request_ip_header.src
        reply_ip_header.protocol = IPProtocol.ICMP
        reply_ip_header.ttl = 64
        #Ethernet_header
        reply_Ethernet_header = Ethernet()
        reply_Ethernet_header.ethertype = EtherType.IPv4

        reply_packet = Packet()
        reply_packet += reply_Ethernet_header
        reply_packet += reply_ip_header
        reply_packet += reply_icmp_header
        # log_info(f"{reply_packet}")
        return reply_packet

    def wait_queue_insert(self,packet,ifaceName):
        IPv4_header = packet.get_header_by_name("IPv4")
        intf = self.net.interface_by_name(ifaceName)
        prefixlen, nexthop, forward_intf = self.forwarding_table.lookup(format(IPv4_header.dst))
        if (nexthop == '0.0.0.0'):
            nextip = format(IPv4_header.dst)
        else:
            nextip = nexthop

        if nextip not in self.wait_packet:
            self.wait_queue.put([nextip, forward_intf, 0, time.time()])
            self.wait_packet[nextip] = [[packet,intf],]
        else:
            self.wait_packet[nextip].append([packet,intf])

    def create_icmp_timeexeceed(self, error_packet, intf):
        i = error_packet.get_header_index(Ethernet)
        del error_packet[i]
         # icmp header
        error_icmp_header = ICMP()
        
        error_icmp_header.icmptype = ICMPType.TimeExceeded
        error_icmp_header.icmpcode = ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired
        error_icmp_header.icmpdata.data = error_packet.to_bytes()[:28]
        log_info(f"{error_icmp_header.icmpdata.data}")
        # ipv4 header
        error_ip_header = IPv4()
        error_ip_header.src = intf.ipaddr
        error_ip_header.dst = error_packet[IPv4].src;
        error_ip_header.protocol = IPProtocol.ICMP
        error_ip_header.ttl = 64
        #Ethernet_header
        error_Ethernet_header = Ethernet()
        error_Ethernet_header.ethertype = EtherType.IPv4

        icmp_error_packet = Packet()
        icmp_error_packet += error_Ethernet_header
        icmp_error_packet += error_ip_header
        icmp_error_packet += error_icmp_header
        # log_info(f"{icmp_error_packet}")
        return icmp_error_packet
 
    def create_icmp_network_unreachable(self, error_packet, intf):
        i = error_packet.get_header_index(Ethernet)
        del error_packet[i]
         # icmp header
        error_icmp_header = ICMP()
        
        error_icmp_header.icmptype = ICMPType.DestinationUnreachable
        error_icmp_header.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable
        error_icmp_header.icmpdata.data = error_packet.to_bytes()[:28]
        log_info(f"{error_icmp_header.icmpdata.data}")
        # ipv4 header
        error_ip_header = IPv4()
        error_ip_header.src = intf.ipaddr
        error_ip_header.dst = error_packet[IPv4].src;
        error_ip_header.protocol = IPProtocol.ICMP
        error_ip_header.ttl = 64
        #Ethernet_header
        error_Ethernet_header = Ethernet()
        error_Ethernet_header.ethertype = EtherType.IPv4

        icmp_error_packet = Packet()
        icmp_error_packet += error_Ethernet_header
        icmp_error_packet += error_ip_header
        icmp_error_packet += error_icmp_header
        # log_info(f"{icmp_error_packet}")
        return icmp_error_packet

    def create_icmp_host_unreachable(self, error_packet, intf):
        i = error_packet.get_header_index(Ethernet)
        del error_packet[i]
         # icmp header
        error_icmp_header = ICMP()
        
        error_icmp_header.icmptype = ICMPType.DestinationUnreachable
        error_icmp_header.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable
        error_icmp_header.icmpdata.data = error_packet.to_bytes()[:28]
        log_info(f"{error_icmp_header.icmpdata.data}")
        # ipv4 header
        error_ip_header = IPv4()
        error_ip_header.src = intf.ipaddr
        error_packet_IPv4 = error_packet.get_header_by_name("IPv4")
        error_ip_header.dst = error_packet_IPv4.src;
        error_ip_header.protocol = IPProtocol.ICMP
        error_ip_header.ttl = 64
        #Ethernet_header
        error_Ethernet_header = Ethernet()
        error_Ethernet_header.ethertype = EtherType.IPv4

        icmp_error_packet = Packet()
        icmp_error_packet += error_Ethernet_header
        icmp_error_packet += error_ip_header
        icmp_error_packet += error_icmp_header
        # log_info(f"{icmp_error_packet}")
        return icmp_error_packet

    def create_icmp_port_unreacheable(self, error_packet, intf):
        i = error_packet.get_header_index(Ethernet)
        del error_packet[i]
         # icmp header
        error_icmp_header = ICMP()
        
        error_icmp_header.icmptype = ICMPType.DestinationUnreachable
        error_icmp_header.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable
        error_icmp_header.icmpdata.data = error_packet.to_bytes()[:28]
        log_info(f"{error_icmp_header.icmpdata.data}")
        # ipv4 header
        error_ip_header = IPv4()
        error_ip_header.src = intf.ipaddr
        error_packet_IPv4 = error_packet.get_header_by_name("IPv4")
        error_ip_header.dst = error_packet_IPv4.src;
        error_ip_header.protocol = IPProtocol.ICMP
        error_ip_header.ttl = 64
        #Ethernet_header
        error_Ethernet_header = Ethernet()
        error_Ethernet_header.ethertype = EtherType.IPv4

        icmp_error_packet = Packet()
        icmp_error_packet += error_Ethernet_header
        icmp_error_packet += error_ip_header
        icmp_error_packet += error_icmp_header
        # log_info(f"{icmp_error_packet}")
        return icmp_error_packet

    def forward_packet(self,ori_packet, intf_name, destmac):
        intf = self.net.interface_by_name(intf_name)
        ori_eth = ori_packet.get_header(Ethernet)
        ori_eth.src = intf.ethaddr
        ori_eth.dst = destmac
        log_info(f"forward:{ori_packet}")
        self.net.send_packet(intf, ori_packet)

    def send_Arp_request(self,destip, intf_name):
        intf = self.net.interface_by_name(intf_name)
        arp_req = create_ip_arp_request(intf.ethaddr, intf.ipaddr, destip)
        log_info(f"arp_request:{arp_req}, time:{time.time()}")
        self.net.send_packet(intf_name,arp_req)


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        
        timestamp, ifaceName, packet = recv
        log_debug (f"In {self.net.name} received packet {packet} on {ifaceName}")

        my_interface = self.net.interfaces()
        my_ip = [intf.ipaddr for intf in my_interface]
        #for ip in my_ip:
            #log_info(f"self interface ip:{ip}")
        # TODO: your logic here
        arp = packet.get_header(Arp)
        IPv4 = packet.get_header_by_name('IPv4')
        #log_info(f"{type(IPv4.dst)}")
        #log_info(f"arp packet tartget ip:{arp.targetprotoaddr}")
        if arp:#arp packtet
            if arp.operation == 1:#request
                self.arptable.update_Arptable(arp.senderprotoaddr, arp.senderhwaddr)
                if arp.targetprotoaddr in my_ip:
                    log_info(f"In {self.net.name} port {ifaceName} receive a arp packet from {arp.senderprotoaddr} to {arp.targetprotoaddr}")
                    intf = self.net.interface_by_ipaddr(arp.targetprotoaddr)
                    Arp_reply = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)
                    log_info(f"arp reply:{Arp_reply}")
                    self.net.send_packet(ifaceName, Arp_reply)
            else:
                if arp.operation == 2:#reply
                    log_info(f"receive arp reply, time:{time.time()}")
                    self.arptable.update_Arptable(arp.senderprotoaddr,arp.senderhwaddr)
        else:#IPv4
            if IPv4:
                IPv4.ttl = IPv4.ttl - 1
                if IPv4.ttl > 0:
                    prefixlen, nexthop, forward_intf = self.forwarding_table.lookup(format(IPv4.dst))
                    if prefixlen != 0:#exist entry in forwarding_table
                        if IPv4.dst not in my_ip:# not send to interfaces of router
                            log_info(f"receive a new packet needed be forwarded: {packet}")
                            self.wait_queue_insert(packet,ifaceName)
                        #self.wait_queue.put([packet, nextip, forward_intf, 0, time.time()])
                        else: # send to interfaces of router
                            icmp_header = packet.get_header_by_name('ICMP')
                            if IPv4.protocol == IPProtocol.ICMP:
                                if icmp_header.icmptype == ICMPType.EchoRequest:#if it is a ICMP echo    
                            # print(icmp_header)
                            #if it is a request echos
                                    log_info(f"receive an icmp request:  {packet}")

                                    icmp_reply_packet = self.create_icmp_echo_reply(icmp_header, IPv4)
                                    log_info(f"send a icmp reply echo:{icmp_reply_packet}")
                                    self.wait_queue_insert(icmp_reply_packet,ifaceName)
                                else:
                                    intf = self.net.interface_by_name(ifaceName)
                                    icmp_error_packet = self.create_icmp_port_unreacheable(packet, intf)

                                    log_info(f"send a icmp error echo:{icmp_error_packet}")
                                    self.wait_queue_insert(icmp_error_packet,ifaceName)
                            else:
                                intf = self.net.interface_by_name(ifaceName)
                                icmp_error_packet = self.create_icmp_port_unreacheable(packet, intf)

                                log_info(f"send a icmp error echo:{icmp_error_packet}")
                                self.wait_queue_insert(icmp_error_packet,ifaceName)

                    else:#dst ip not in forwarding_table
                        intf = self.net.interface_by_name(ifaceName)
                        icmp_error_packet = self.create_icmp_network_unreachable(packet, intf)
                        
                        log_info(f"send a icmp error echo:{icmp_error_packet}")
                        self.wait_queue_insert(icmp_error_packet, ifaceName)
                else:#time exceed 
                    intf = self.net.interface_by_name(ifaceName)
                    icmp_error_packet = self.create_icmp_timeexeceed(packet, intf)
                    
                    log_info(f"send a icmp error echo:{icmp_error_packet}")
                    self.wait_queue_insert(icmp_error_packet,ifaceName)

    def wait_queue_operation(self, wait_queue, wait_packet,arptable):
        while True:
            #log_info("debug")
            if not wait_queue.empty():

                entry = wait_queue.get()
                nextip = entry[0]
                dst_intf = entry[1]
                send_cnt = entry[2]
                timestamp = entry[3]

                destmacaddr = self.arptable.lookup(nextip)
                if destmacaddr:
                    packetlist = wait_packet[nextip]
                    for packet in packetlist:
                        self.forward_packet(packet[0], dst_intf, destmacaddr)
                    #time.sleep(1.0)s
                    wait_packet.pop(nextip)
                else:
                    #log_info(f"{entry[4]}, {time.time()}")
                    if send_cnt == 0:#first request
                        self.send_Arp_request(nextip, dst_intf)
                        entry[2] = send_cnt + 1
                        entry[3] = time.time()
                        wait_queue.put(entry)
                        time.sleep(0.2)
                    else:
                        if timestamp + 1 < time.time():
                            if (send_cnt < 5):
                                self.send_Arp_request(nextip, dst_intf)
                                entry[2] = send_cnt + 1
                                entry[3] = time.time()
                                wait_queue.put(entry)
                                time.sleep(0.2)
                            else:
                                for packet in wait_packet[nextip]:
                                    intf = packet[1]
                                    icmp_error_packet = self.create_icmp_host_unreachable(packet[0], intf)
                                    log_info(f"send a icmp error echo:{icmp_error_packet}")
                                    self.wait_queue_insert(icmp_error_packet,intf.name)
                                wait_packet.pop(nextip)
                                
                        else:
                            wait_queue.put(entry)
                    '''
                    if entry[3] == 0:#first request
                        self.send_Arp_request(entry[1], entry[2])
                        time.sleep(0.2)
                        entry[3] = entry[3] + 1
                        entry[4] = time.time()
                        wait_queue.put(entry)
                    else:
                        if entry[4] + 1 < time.time():
                            if entry[3] < 5:
                                self.send_Arp_request(entry[1], entry[2])
                                time.sleep(0.2)
                                entry[3] = entry[3] + 1
                                entry[4] = time.time()
                                wait_queue.put(entry)
                        else:#time < 1.0sss
                             wait_queue.put(entry)
                    '''


        '''
        for entry in self.wait_queue.queue:
            #log_info(f"debug:{entry}")
            destmacaddr = self.arptable.lookup(entry[1])
            #log_info(f"debug:{destmacaddr}")
            if destmacaddr:
                self.forward_packet(entry[0],entry[2],destmacaddr)
                self.wait_queue.queue.remove(entry)
            else:
                timestamp = time.time()
                if entry[4] + 1 < timestamp:
                    if entry[3] < 5:
                        self.send_Arp_request(entry[1], entry[2])
                        entry[3] = entry[3] + 1
                        entry[4] = timestamp
                    else:
                        self.wait_queue.queue.remove(entry)
    '''        

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        send_thread = threading.Thread(target = self.wait_queue_operation, args=(self.wait_queue, self.wait_packet,self.arptable))
        send_thread.start()
        while True:
            try:

                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                #self.wait_queue_operation()
                continue
            except Shutdown:
                break
            #log_info(f"receive a packet, {time.time()}")
            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
