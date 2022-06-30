'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import time
from switchyard.lib.userlib import *

def Delete_lru(table):
    age = 0
    delete_key = 0
    for key in table:
        if table[key][1] >= age:
            age = table[key][1]
            delete_key = key
    table.pop(delete_key)


def Update_forwardtable(forward_table, src_mac, dst_mac, fromIface):
    max_capcity = 5
    if src_mac in forward_table:
        if fromIface != forward_table[src_mac][0]:
            forward_table[src_mac][0] = fromIface
    else:
        for key in forward_table:
            forward_table[key][1] = forward_table[key][1] + 1
        if (len(forward_table) >= max_capcity):
            Delete_lru(forward_table)
        forward_table[src_mac] = [fromIface, 0] 
    if dst_mac in forward_table:
        for key in forward_table:
            forward_table[key][1] = forward_table[key][1] + 1
        forward_table[dst_mac][1] = 0
        
    for key in forward_table:
        log_info(f"(mac:{key},port:{forward_table[key][0]},age:{forward_table[key][1]})")   

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

        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
            Update_forwardtable(forward_table,eth.src,eth.dst,fromIface)
        else:
            Update_forwardtable(forward_table,eth.src,eth.dst,fromIface)
            if eth.dst in forward_table:
                forward_interface = forward_table[eth.dst][0]
                intf = net.interface_by_name(forward_interface)
                log_info (f"Fowarding packet {packet} to {intf.name}")
                net.send_packet(intf, packet)
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
    net.shutdown()
