'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import time
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    forward_table = dict()

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        timestamp = time.time()
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
            forward_table[eth.src] = [fromIface, timestamp]
        else:
            log_info(f"timestamp:{timestamp}")
            forward_table[eth.src] = [fromIface, timestamp]
            if eth.dst in forward_table:
                if forward_table[eth.dst][1] + 10 >= timestamp:
                    forward_interface = forward_table[eth.dst][0]
                    intf = net.interface_by_name(forward_interface)
                    log_info (f"Fowarding packet {packet} to {intf.name}")
                    net.send_packet(intf, packet)
                else:
                    forward_table.pop(eth.dst)
                    for intf in my_interfaces:
                        if fromIface!= intf.name:
                            log_info (f"Flooding packet {packet} to {intf.name}")
                            net.send_packet(intf, packet)
            else: 
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
    net.shutdown()
