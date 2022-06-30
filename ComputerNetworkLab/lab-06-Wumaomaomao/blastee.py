#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = IPv4Address(blasterIp);
        log_info(f"blasterIp initialization:{self.blasterIp}, class:{type(self.blasterIp)}");
        self.num = int(num);
        log_info(f"num initialization:{self.num}, class:{type(self.num)}");
        ...

    def Create_ACK_packet(self, recv_packet, intf_name):
        intf = self.net.interface_by_name(intf_name);
        #Ethernet
        recv_Ethernet_header = recv_packet.get_header_by_name("Ethernet")
        ACK_Ethernet_header = Ethernet()
        ACK_Ethernet_header.ethertype = EtherType.IPv4
        ACK_Ethernet_header.src = intf.ethaddr
        ACK_Ethernet_header.dst = recv_Ethernet_header.src
        #IPv4
        ACK_IPv4_header = IPv4()
        ACK_IPv4_header.protocol = IPProtocol.UDP
        ACK_IPv4_header.src = intf.ipaddr
        ACK_IPv4_header.dst = self.blasterIp
        ACK_IPv4_header.ttl = 64
        #UDP
        ACK_UDP_header = UDP()
        ACK_UDP_header.src = 1234
        ACK_UDP_header.dst = 4321
        #RawPacketContent
        recv_RawPckectContent_header = recv_packet.get_header_by_name("RawPacketContents")
        recv_RawPacketContent = recv_RawPckectContent_header.to_bytes()
        recv_SequenceNum_bytes =  recv_RawPacketContent[0:4];
        recv_SequenceNum = int.from_bytes(recv_SequenceNum_bytes,'big')
        recv_payload =  recv_RawPacketContent[7:15]

        ACK_SequenceNum = recv_SequenceNum;
        ACK_SequenceNum_bytes = ACK_SequenceNum.to_bytes(4,byteorder='big')
        ACK_RawPacketContents = ACK_SequenceNum_bytes + recv_payload;
         

        ACK_packet = Packet()
        ACK_packet += ACK_Ethernet_header
        ACK_packet += ACK_IPv4_header
        ACK_packet += ACK_UDP_header
        ACK_packet += ACK_RawPacketContents;
        log_info(f"create a new ACK:{ACK_packet}")
        return ACK_packet

        

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")

        ACK_packet = self.Create_ACK_packet(packet, fromIface);
        self.net.send_packet(fromIface, ACK_packet);

    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
