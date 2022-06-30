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

class wait_queue(object):
    def __init__(self, queue):
        self.queue = queue
    def insert(self,packet, nextip, intf_name, time_cnt):
        timestamp = time.time()
        self.queue.append([packet, nextip, intf_name, time_cnt, timestamp])

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
        else:
            if IPv4:
                IPv4.ttl = IPv4.ttl - 1
                prefixlen, nexthop, forward_intf = self.forwarding_table.lookup(format(IPv4.dst))
                if prefixlen != 0:#exist entry in forwarding_table
                    if IPv4.dst not in my_ip:# not send to interfaces of router
                        if (nexthop == '0.0.0.0'):
                            nextip = format(IPv4.dst)
                        else:
                            nextip = nexthop
                        # destmacaddr = self.arptable.lookup(nextip)
                        log_info("receive a new packet needed be forwarded")
                        if nextip not in self.wait_packet:
                            self.wait_queue.put([nextip, forward_intf, 0, time.time()])
                            self.wait_packet[nextip] = [packet,]
                        else:
                            self.wait_packet[nextip].append(packet)
                        #self.wait_queue.put([packet, nextip, forward_intf, 0, time.time()])

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
                        self.forward_packet(packet, dst_intf, destmacaddr)
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
