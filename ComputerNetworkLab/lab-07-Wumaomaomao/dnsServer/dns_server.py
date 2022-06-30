'''DNS Server for Content Delivery Network (CDN)
'''

import sys
import random
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math

import re
from collections import namedtuple


__all__ = ["DNSServer", "DNSHandler"]


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = []
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        #open the file and obtain the content
        dns_src_file = open(dns_file,'r')
        text = dns_src_file.readlines()
        #for each row record
        for entry in text:
            cells = entry.split()
            #exist wildcark mask, append a flag
            if cells[0][-1] == '.':#omit root domain name flag
                cells[0] = cells[0][0:-1]
            if cells[0][0] == '*':
                WildCard = "True"
                Domain_name = cells[0][2:]
                Domain_name = "[a-zA-Z0-9.]*" + Domain_name + "$"
            else:
                WildCard = "False"
                Domain_name = cells[0]
                Domain_name = Domain_name + "$"
            
            #if cells[1] == "A":
             #   geographicaladdr = IP_Utils.getIpLocation(cells[2][0])
            #  print(f"geographicaladdr:{geographicaladdr},type:{type(geographicaladdr)}")
            Record_type = cells[1]
            cells.pop(0)
            cells.pop(0)
            Record_values = cells;
            self._dns_table.append([WildCard,Domain_name,Record_type,Record_values])
            print(f"WildCard:{WildCard},Domain_name:{Domain_name},Record_type:{Record_type},Record_values:{Record_values}")


        
    

    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)

    def calc_distance(self, pointA, pointB):
        ''' TODO: calculate distance between two points '''
        # I have finished the task in function "get_response"
        ...

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address
        match_record = None
        if request_domain_name[-1] == '.':
            match_domain_name = request_domain_name[0:-1]
        else:
            match_domain_name = request_domain_name
        for record in self.table:
            if re.match(record[1], match_domain_name):
                match_record = record
                break
        if match_record != None:
            if match_record[2] == "CNAME":
                response_type = "CNAME"
                response_val = match_record[3][0]
            else:
                recordcnt = len(match_record[3])
                if recordcnt == 1:#only one ip address
                    response_type = "A"
                    response_val = match_record[3][0]
                else:
                    geographicaladdr = IP_Utils.getIpLocation(client_ip)
                    
                    #print(f"geographicaladdr:{geographicaladdr},type:{type(geographicaladdr)}")
                    if geographicaladdr == None:
                        index = random.randint(0,recordcnt)
                        response_type = "A"
                        response_val = match_record[3][index]
                    else:
                        dist = -100#initialize the dist with a min value
                        for ipaddress in match_record[3]:
                            dst_geographicaladdr = IP_Utils.getIpLocation(ipaddress)
                            dst_dist = (dst_geographicaladdr[0] - geographicaladdr[0])**2 + (dst_geographicaladdr[1] - geographicaladdr[0])**2
                            if dist == -100:
                                dist = dst_dist
                                response_type = "A"
                                response_val = ipaddress
                            else:
                                if dst_dist < dist:
                                    dist = dst_dist
                                    response_type = "A"
                                    response_val = ipaddress



        # -------------------------------------------------
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
