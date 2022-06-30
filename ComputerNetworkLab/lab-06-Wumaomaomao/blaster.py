#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

class SLidingWindow:
    def __init__(self, size):
        self.SW = dict()
        self.Maxsize = size
        self.LHS = 1
        self.RHS = 0
        self.ResendHead = -1
        self.ResendPos = 0
        self.timer = time.time()


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):

        self.net = net
        self.Starttime = time.time()
        self.reTX = 0
        self.coarseTO = 0
        self.TotalSendbytes = 0
        self.TotalSuccSendbytes = float(0)
        self.recvTimeout = float(recvTimeout) / 1000
        # TODO: store the parameters
        self.Window = SLidingWindow(int(senderWindow))
        self.blasteeIp = IPv4Address(blasteeIp)
        self.num = int(num)
        self.length = int(length)
        self.timeout = float(timeout) / 1000

        

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        recv_RawPacketContent_header = packet.get_header_by_name("RawPacketContents")
        recv_RawPacketContent = recv_RawPacketContent_header.to_bytes()
        recv_SequenceNum_bytes =  recv_RawPacketContent[0:4]
        recv_SequenceNum = int.from_bytes(recv_SequenceNum_bytes,'big')
        log_info(f"Ack Sequence:{recv_SequenceNum}")

        if recv_SequenceNum in range(self.Window.LHS, self.Window.RHS + 1):
            if self.Window.SW[recv_SequenceNum][1] == 'NotAck':
                self.TotalSuccSendbytes += self.length
                Throughput = self.TotalSendbytes / (time.time() - self.Starttime)
                Goodput = self.TotalSuccSendbytes / (time.time() - self.Starttime)
                #Goodput = 
                print(f"Ack Packet Sequence {recv_SequenceNum} \nTotal TX time:{time.time() - self.Starttime} \nNumber of reTX:{self.reTX} \nCoarse Timeouts:{self.coarseTO}")
                print(f"Throughput(Bps):{Throughput}")
                print(f"Goodput(Bps):{Goodput}\n")
                self.Window.SW[recv_SequenceNum][1] = 'Ack'
    def Create_Packet(self ,SequenceNum):
        pkt = Ethernet() + IPv4() + UDP()
        pkt[0].ethertype = EtherType.IPv4
        pkt[0].src = '10:00:00:00:00:01'
        pkt[0].dst = '40:00:00:00:00:01'    

        pkt[1].protocol = IPProtocol.UDP
        pkt[1].src = IPv4Address('192.168.100.1')
        pkt[1].dst = self.blasteeIp
        pkt[1].ttl = 64

        pkt[2].src = 4321
        pkt[2].dst = 1234
        SequenceNum_bytes = SequenceNum.to_bytes(4,byteorder='big')
        #log_info(f"{SequenceNum_bytes}")
        #Test_SequenceNum = int.from_bytes(SequenceNum_bytes,'big')
        #log_info(f"{Test_SequenceNum}")
        length_bytes = self.length.to_bytes(2,byteorder='big')
        payload = 0
        payload_bytes = payload.to_bytes(self.length,byteorder="big")
        RawPacketContents_bytes = SequenceNum_bytes + length_bytes + payload_bytes

        pkt += RawPacketContents_bytes
        log_info(f"Create a new Packet to be sent:{pkt} Sequence = {SequenceNum}")
        #log_info(f"RawPacket class:{type(RawPacketContents_bytes)}")


        return pkt

    def handle_no_packet(self):
        log_debug("Didn't receive anything")

        list = range(self.Window.LHS, self.Window.RHS + 1)
        for idx in list:
            if self.Window.SW[idx][1] == 'Ack':
                self.Window.LHS += 1;
                self.Window.timer = time.time()
                self.Window.ResendHead = -1 
            else:
                break
            #if self.Window.LHS == self.num + 1:
             #   self.net.shutdown()


        if self.Window.RHS - self.Window.LHS + 1 < 5:
            if self.Window.RHS < self.num:
                #while self.Window.RHS - self.Window.LHS + 1 < 5 :
                    # if self.Window.RHS < self.num:
                self.Window.RHS += 1
                send_packet = self.Create_Packet(self.Window.RHS)
                self.TotalSendbytes += self.length
                intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
                self.net.send_packet(intf.name, send_packet)
                self.Window.SW[self.Window.RHS] = [send_packet, 'NotAck',time.time(),0]
            

        #log_info(f"timer:{self.Window.timer}, curtime:{time.time()}")
        '''if self.Window.timer + self.timeout < time.time() and self.Window.LHS <= self.num:
            if self.Window.ResendHead == -1:
                self.coarseTO += 1
                self.Window.ResendHead = self.Window.LHS
                self.Window.ResendPos = self.Window.ResendHead
                send_packet = self.Window.SW[self.Window.ResendPos][0]
                intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
                intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
                RawPackectContent_header = send_packet.get_header_by_name("RawPacketContents")
                
                RawPackectContent = RawPackectContent_header.to_bytes()
                SequenceNum_bytes =  RawPackectContent[0:4];
                #log_info(f"{SequenceNum_bytes}")
                SequenceNum = int.from_bytes(SequenceNum_bytes,'big')
                log_info(f"Resend the packet: {send_packet}, SequenceNum = {SequenceNum}")
                #self.Window.SW[idx][3] += 1
                self.reTX += 1
                self.TotalSendbytes += self.length
                self.net.send_packet(intf.name, send_packet)
                if self.Window.ResendPos == self.Window.RHS:
                    self.Window.ResendPos = self.Window.ResendHead
                else:
                    self.Window.ResendPos = self.Window.ResendPos + 1
                while self.Window.SW[self.Window.ResendPos][1] =='Ack' and self.Window.ResendPos != self.Window.ResendHead:
                    if self.Window.ResendPos == self.Window.RHS:
                        self.Window.ResendPos = self.Window.ResendHead
                    else:
                        self.Window.ResendPos = self.Window.ResendPos + 1
            else:
                if self.Window.ResendPos == self.Window.ResendHead:#a cycle end
                    self.Window.timer = time.time()
                    self.Window.ResendHead = -1
                else:
                    send_packet = self.Window.SW[self.Window.ResendPos][0]
                    intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
                    intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
                    RawPackectContent_header = send_packet.get_header_by_name("RawPacketContents")
                
                    RawPackectContent = RawPackectContent_header.to_bytes()
                    SequenceNum_bytes =  RawPackectContent[0:4];
                #log_info(f"{SequenceNum_bytes}")
                    SequenceNum = int.from_bytes(SequenceNum_bytes,'big')
                    log_info(f"Resend the packet: {send_packet}, SequenceNum = {SequenceNum}")
                #self.Window.SW[idx][3] += 1
                    self.reTX += 1
                    self.TotalSendbytes += self.length
                    self.net.send_packet(intf.name, send_packet)
                    if self.Window.ResendPos == self.Window.RHS:
                        self.Window.ResendPos = self.Window.ResendHead
                    else:
                        self.Window.ResendPos = self.Window.ResendPos + 1
                    while self.Window.SW[self.Window.ResendPos][1] =='Ack' and self.Window.ResendPos != self.Window.ResendHead:
                        if self.Window.ResendPos == self.Window.RHS:
                            self.Window.ResendPos = self.Window.ResendHead
                        else:
                            self.Window.ResendPos = self.Window.ResendPos + 1

            '''
        if self.Window.timer + self.timeout < time.time() and self.Window.LHS <= self.num:#timeout
            self.coarseTO += 1
            self.Window.ResendHead = self.Window.LHS
            self.Window.ResendPos = self.Window.ResendHead
            send_packet = self.Window.SW[self.Window.ResendPos][0]
            intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
            intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
            RawPackectContent_header = send_packet.get_header_by_name("RawPacketContents")
                
            RawPackectContent = RawPackectContent_header.to_bytes()
            SequenceNum_bytes =  RawPackectContent[0:4];
                #log_info(f"{SequenceNum_bytes}")
            SequenceNum = int.from_bytes(SequenceNum_bytes,'big')
            log_info(f"Resend the packet: {send_packet}, SequenceNum = {SequenceNum}")
                #self.Window.SW[idx][3] += 1
            self.reTX += 1
            self.TotalSendbytes += self.length
            self.net.send_packet(intf.name, send_packet)
            if self.Window.ResendPos == self.Window.RHS:
                self.Window.ResendPos = self.Window.ResendHead
            else:
                self.Window.ResendPos = self.Window.ResendPos + 1
            while self.Window.SW[self.Window.ResendPos][1] =='Ack' and self.Window.ResendPos != self.Window.ResendHead:
                if self.Window.ResendPos == self.Window.RHS:
                    self.Window.ResendPos = self.Window.ResendHead
                else:
                    self.Window.ResendPos = self.Window.ResendPos + 1
            #list = range(self.Window.LHS, self.Window.RHS + 1)
            #log_info(f"{list}")
            #for idx in list:
                
                
            self.Window.timer = time.time()  

        # Creating the headers for the packet
        elif self.Window.ResendHead != -1:
            if self.Window.ResendPos == self.Window.ResendHead:#a cycle end
                    self.Window.timer = time.time()
                    self.Window.ResendHead = -1
            else:
                send_packet = self.Window.SW[self.Window.ResendPos][0]
                intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
                intf = self.net.interface_by_ipaddr(IPv4Address('192.168.100.1'))
                RawPackectContent_header = send_packet.get_header_by_name("RawPacketContents")
                
                RawPackectContent = RawPackectContent_header.to_bytes()
                SequenceNum_bytes =  RawPackectContent[0:4];
                #log_info(f"{SequenceNum_bytes}")
                SequenceNum = int.from_bytes(SequenceNum_bytes,'big')
                log_info(f"Resend the packet: {send_packet}, SequenceNum = {SequenceNum}")
                #self.Window.SW[idx][3] += 1
                self.reTX += 1
                self.TotalSendbytes += self.length
                self.net.send_packet(intf.name, send_packet)
                if self.Window.ResendPos == self.Window.RHS:
                    self.Window.ResendPos = self.Window.ResendHead
                else:
                    self.Window.ResendPos = self.Window.ResendPos + 1
                while self.Window.SW[self.Window.ResendPos][1] =='Ack' and self.Window.ResendPos != self.Window.ResendHead:
                    if self.Window.ResendPos == self.Window.RHS:
                        self.Window.ResendPos = self.Window.ResendHead
                    else:
                        self.Window.ResendPos = self.Window.ResendPos + 1
                

        # Do other things here and send packet
        ...

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout )
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
