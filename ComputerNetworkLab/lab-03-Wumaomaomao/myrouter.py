#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

class Arptable(object):
    def __init__(self, table):
        self.table = table
    def timeout(self):
        delete_key =[];
        timestamp = time.time()
        for key in self.table:
            if (self.table[key][1] + 10 <= timestamp):
                delete_key.append(key);
        for key in delete_key:
            self.table.pop(key)

    def update_Arptable(self, ipaddr, macaddr):
        self.timeout()
        timestamp = time.time()
        self.table[ipaddr] = [macaddr, timestamp]
        for key in self.table:
            log_info(f"ipaddr:{key} macaddr:{self.table[key][0]} timestamp:{self.table[key][1]}")

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arptable = Arptable(dict())
        # other initialization stuff here

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        
        timestamp, ifaceName, packet = recv
        log_debug (f"In {self.net.name} received packet {packet} on {ifaceName}")

        my_interface = self.net.interfaces()
        my_ip = [intf.ipaddr for intf in my_interface]
        #for ip in my_ip:
            #log_info(f"self interface ip:{ip}")
        # TODO: your logic here
        arp = packet.get_header(Arp)
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

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

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
