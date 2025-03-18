import time
from scapy.all import *
import collections
from binascii import hexlify
import logging
from enum import Enum
from pprint import pprint
logging_level=3
import hashlib
import ipaddress
import random
import mysql.connector
import os
import ipaddress
import bisect
import sys
from scapy.all import *
from collections import deque 
import random
import socket
import psutil
import requests


verbose=1
if verbose == 0:
    logging.root.setLevel(logging.NOTSET)
    logging.basicConfig(level=logging.NOTSET)
elif verbose == 1:
    logging.root.setLevel(logging.WARNING)
    logging.basicConfig(level=logging.WARNING)
elif verbose == 2:
    logging.root.setLevel(logging.ERROR)
    logging.basicConfig(level=logging.ERROR)




class Packet_Wrapper:
    def __init__(self,current_packet,packet_number):
        self.packet = current_packet
        self.packet_num=packet_number


    
class Open_Port_Wrapper:
    def __init__(self,proto,current_packet):
        self.packet = current_packet
        self.proto=proto
        
class Ports:
    def __init__(self,args):
        self.currently_open_ip_list = {}
        self.previously_open_ip_list = {}
        self.report_unwanted=[]
        self.packet_buffer = collections.deque()
        self.packet_watch_list = collections.deque()
        self.ARP_requests = collections.deque()
        self.ARP_same_timestamp = collections.deque()
        self.timer=0
        self.gui_currently_open_ip_list_has_updates=0
        self.SYN_reply_timeout=0.5
        self.ARP_reply_timeout=0.5
        self.Recently_closed_port_timeout=0.5
        self.num_preprocessing_packets=300
        self.gui=args.gui
        self.database=args.database
        self.verbose=args.verbose
        self.num_total_tcp_packets=0
        self.num_unwanted_tcp_packets=0
        self.lookup_network_information_list={}
        self.report_output_buffer=[]
        self.report_batch_length=10
        self.args=args
        self.check_if_ip_changed_packet_interval=2000
        self.external_ip=""
        self.internal_ip=""
        self.asn=0
        self.external_network_information=""
        self.internal_network_information=""
        self.max_unwanted_buffer_size=1000
        self.internal_ip_equals_external_ip=""
        self.internal_is_private=""
        self.external_is_private=""



    def check_ip_is_private(self,ip_str):
        try:
            # Create an IP address object (works for both IPv4 and IPv6)
            ip_obj = ipaddress.ip_address(ip_str)
        
            if ip_obj.is_private:
                return(f"True")
            else:
                return(f"False")
        except ValueError:
            return(f" is not a valid IP address.")

    def update_external_ip(self):
        response = requests.get("https://ipinfo.io/what-is-my-ip")
        response=response.json()
        self.external_ip=response["ip"]
        self.log_local_terminal_and_GUI_WARN(f"external IP found {self.external_ip}" ,6)
        self.update_external_network_information(self.external_ip)
        self.external_is_private=self.check_ip_is_private(self.external_ip)


    def update_external_network_information(self,external_ip):
        self.external_network_information=self.lookup_network_information(external_ip)
        self.log_local_terminal_and_GUI_WARN(f"external_network_information found {self.external_network_information}" ,6)


    def update_internal_network_information(self,internal_ip):
        self.internal_network_information=self.lookup_network_information(internal_ip)
        self.log_local_terminal_and_GUI_WARN(f"internal_network_information found {self.internal_network_information}" ,6)


    def ip_to_int(self,ip_str):
        return int(ipaddress.ip_address(ip_str))

    def find_file_for_second_octet(self,directory, second_octet):
        # List all .txt files in the directory
        files = [f for f in os.listdir(directory) if f.endswith('.txt')]
        # Extract the start octets
        starts = []
        for filename in files:
            base = os.path.splitext(filename)[0]
            try:
                start_val = int(base)
                starts.append(start_val)
            except ValueError:
                # Skip files that don't follow the naming convention
                continue

        # Sort the start values
        starts.sort()
        # Use binary search to find the file that covers this second_octet
        pos = bisect.bisect_right(starts, second_octet) - 1
        if pos < 0:
            # No start <= second_octet
            self.lookup_network_information_list[ip_str]=("error", "No start <= second_octet")
            return ("error", "No start <= second_octet","None")

        chosen_start = starts[pos]
        return os.path.join(directory, f"{chosen_start}.txt")

    def lookup_network_information(self,ip_str, base_dir="hierarchical_IP_tree"):
        ip_str=str(ip_str)
        if ip_str in self.lookup_network_information_list:
            return self.lookup_network_information_list[ip_str]

        parts = ip_str.split('.')
        if len(parts) != 4:
            self.log_local_terminal_and_GUI_WARN("Invalid IPv4 address.",3)
            self.lookup_network_information_list[ip_str]=("error", "Invalid IPv4 address 4 parts")
            return ("error", "Invalid IPv4 address 4 parts","None")
        try:
            first_octet = int(parts[0])
            second_octet = int(parts[1])
        except ValueError:
            self.log_local_terminal_and_GUI_WARN("Invalid IPv4 address.",3)
            self.lookup_network_information_list[ip_str]=("error", "Invalid IPv4 address octets")
            return ("error", "Invalid IPv4 address octets","None")

        # Construct the directory for the first octet
        first_octet_dir = os.path.join(base_dir, str(first_octet))
        if not os.path.isdir(first_octet_dir):
            # No directory for this first octet
            self.lookup_network_information_list[ip_str]=("error", "No directory for this first octet")
            return ("error", "first octet filepath","None")

        # Find the appropriate file for the second octet
        file_path = self.find_file_for_second_octet(first_octet_dir, second_octet)
        if file_path is None or not os.path.exists(file_path):
            # No file for this second octet range
            self.lookup_network_information_list[ip_str]=("error", "second octet filepath")
            return ("error", "second octet filepath","None")

        lookup_network_information_int = self.ip_to_int(ip_str)

        # Search within this file's ranges
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts_line = line.split(',')
                if len(parts_line) < 5:
                    continue
                start_ip_str, end_ip_str, net_type, country, asn = parts_line[0], parts_line[1], parts_line[2], parts_line[3], parts_line[4]

                try:
                    start_ip_int = self.ip_to_int(start_ip_str)
                    end_ip_int = self.ip_to_int(end_ip_str)
                except ValueError:
                    # Skip invalid IP
                    continue

                if start_ip_int <= lookup_network_information_int <= end_ip_int:
                    self.lookup_network_information_list[ip_str]=(net_type, country,asn)
                    return (net_type, country,asn)


        self.lookup_network_information_list[ip_str]=("None", "IP not in dataset")
        return ("None", "IP not in dataset","None")

    
    def open_port(self,ip,port,proto,current_packet):
        if "R" not in current_packet.packet[TCP].flags:
            logging.info(f'Call to port open {port} on {ip} for {proto} ')
            #can we differentiate incoming or outgoing traffic?
            #subnet inference (https://dl.ifip.org/db/conf/tma/tma2019/TMA_Paper_10.pdf) https://github.com/JefGrailet/WISE
            #maybe just ask subnet for now from user?
            #If we see layer 2 traffic to or from an IP we know it's on our subnet
            if self.is_port_open(ip,port,proto) is True:
                #raise NameError(f'Trying to open an already opened port {port} on {ip} for {proto}')
                #print(f'Trying to open an already opened port {port} on {ip} for {proto}')
                pass
            else:
                if ip not in self.currently_open_ip_list:
                    #if we don't have this IP, is this a syn packet to open the port? If not this traffic is unwanted.
                    self.currently_open_ip_list[ip]={}
                    logging.info(f'open_port: IP not found in self.currently_open_ip_list {ip} ')
                if port not in self.currently_open_ip_list[ip]:
                    logging.info(f'open_port:  {port} port not in self.currently_open_ip_list[ip]')
                    self.currently_open_ip_list[ip][port]=[]
                self.currently_open_ip_list[ip][port].append(Open_Port_Wrapper(proto,current_packet))
                
                #logging.warn(f'Port opened {port} on {ip} for {proto} {self.currently_open_ip_list[ip][port]}')
                self.log_local_terminal_and_GUI_WARN(f'Port opened {port} on {ip} for {proto} Packet Number {current_packet.packet_num}  {current_packet.packet.payload}',3)
                justification=f"Justification: Packet Number {current_packet.packet_num}  {current_packet.packet.payload}"
                if self.gui:
                    eel.AddPort(ip,port,proto,justification)
                
                #for IPs in   Port_status.currently_open_ip_list:
                    #logging.info(f" After port opened, new IP list IPs {IPs} {Port_status.currently_open_ip_list[IPs]} ")
            
    def close_port(self,ip,port,proto,historical_unacked_syn):
        #TODO: Logic for when we get a SYN on a port we think is open and we don't SYN ACK
        
        if self.is_port_open(ip,port,proto):
            self.log_local_terminal_and_GUI_WARN(f"close_port called for {port} on {ip} for {proto} because of un-acked packet{historical_unacked_syn.packet_num} {historical_unacked_syn.packet.payload}, {len(self.currently_open_ip_list[ip][port])} protocols open for this port",2)
            for index in range(len(self.currently_open_ip_list[ip][port])):
                self.log_local_terminal_and_GUI_WARN(f"IN LIST Protocol:{self.currently_open_ip_list[ip][port][index].proto}  Triggering Packet: {self.currently_open_ip_list[ip][port][index].packet.packet_num} {self.currently_open_ip_list[ip][port][index].packet.packet} \n",2) 
        

            for x in range(len(self.currently_open_ip_list[ip][port]) - 1, -1, -1):
                open_port_wrapper=self.currently_open_ip_list[ip][port][x]
                #for open_port_wrapper in self.currently_open_ip_list[ip][port]:
                self.log_local_terminal_and_GUI_WARN(f' found proto on this port {open_port_wrapper.proto}n',0)
                if proto in open_port_wrapper.proto:
                    self.log_local_terminal_and_GUI_WARN(f' \nFOUND THIS IN LIST WILL BE CLOSED\n',0)
                    self.log_local_terminal_and_GUI_WARN(f"Port {port} on {ip} for {proto} closed because of un-acked packet{historical_unacked_syn.packet_num} {historical_unacked_syn.packet.payload}, {len(self.currently_open_ip_list[ip][port])} protocols open for this port",3)
                    self.currently_open_ip_list[ip][port].pop(x)
                    if self.gui:
                        eel.RemovePort(ip,port,proto)
                else:
                    self.log_local_terminal_and_GUI_WARN(f"\nCouldn't find this proto in our list??? {self.currently_open_ip_list[ip][port]}\n",0)
            self.log_local_terminal_and_GUI_WARN(f"Now {len(self.currently_open_ip_list[ip][port])} protocols open for this port",0)
            for index in range(len(self.currently_open_ip_list[ip][port])):
                self.log_local_terminal_and_GUI_WARN(f"IN LIST Protocol:{self.currently_open_ip_list[ip][port][index].proto}  Triggering Packet: {self.currently_open_ip_list[ip][port][index].packet.packet_num} {self.currently_open_ip_list[ip][port][index].packet.packet} \n\n",0) 
        
        else:
            self.log_local_terminal_and_GUI_WARN(f"Close port called (but port was unopen so no action taken) for port {port} on {ip} for {proto} because of un-acked packet {historical_unacked_syn.packet.payload}",0)
        

                    
        #add the now closed port to the previously open port listif ip not in self.currently_open_ip_list:
        logging.info(f'self.was_port_previously_open(historical_unacked_syn) {self.was_port_previously_open(historical_unacked_syn)}') #TODO WORK HERE
        '''if self.was_port_previously_open(historical_unacked_syn,port) is True:
            pass
        else:
        '''
        logging.info(f'self.previously_open_ip_list {self.previously_open_ip_list}')
        logging.info(f'ip not in self.previously_open_ip_list {ip not in self.previously_open_ip_list}')
        if ip not in self.previously_open_ip_list:
            #if we don't have this IP, is this a syn packet to open the port? If not this traffic is unwanted.
            self.previously_open_ip_list[ip]={}
            logging.info(f'ADDED ip not in self.previously_open_ip_list {ip not in self.previously_open_ip_list}  {self.previously_open_ip_list}')
            logging.info(f'closed port: IP not found in self.previously_open_ip_list {ip} ')
        self.log_local_terminal_and_GUI_WARN(f'port not in self.previously_open_ip_list[ip] {port not in self.previously_open_ip_list[ip]}',2)
        if port not in self.previously_open_ip_list[ip]:
            logging.info(f'port not in self.previously_open_ip_list[ip]:  {port} port not in self.previously_open_ip_list[ip]')
            self.previously_open_ip_list[ip][port]=[]
            logging.info(f'self.previously_open_ip_list[ip] {self.previously_open_ip_list[ip]} self.previously_open_ip_list[ip][port] {self.previously_open_ip_list[ip][port]}')
        self.previously_open_ip_list[ip][port].append(historical_unacked_syn)
        #logging.warn(f'Port opened {port} on {ip} for {proto} {self.previously_open_ip_list[ip][port]}')
        self.log_local_terminal_and_GUI_WARN(f'Port added to previously_open_ip_list {port} on {ip} for {proto} ',2)

        
        
        if ip in self.currently_open_ip_list:
            if (port in self.currently_open_ip_list[ip]):
                if len(self.currently_open_ip_list[ip][port]) ==0:
                    del self.currently_open_ip_list[ip][port]
        


    def is_port_open(self,ip,port,proto):
        port_open=False
        if ip in self.currently_open_ip_list:
            if port in self.currently_open_ip_list[ip]:
                #if proto in self.currently_open_ip_list[ip][port]:
                for portwrapper in self.currently_open_ip_list[ip][port]:
                    self.log_local_terminal_and_GUI_WARN(f"IP {ip} has port {port} open for proto {proto} Triggering Packet: {portwrapper.packet.packet_num} {portwrapper.packet.packet}",0)
                    if portwrapper.proto == proto:
                        port_open=True
                        self.log_local_terminal_and_GUI_WARN(f"This matches proto port and IP so yes port is open",0)
        return port_open
        
        
        
    def was_port_previously_open(self,current_packet):
        ip= current_packet.packet[IP].dst
        port=current_packet.packet[TCP].dport
        port_open=False
        if ip in self.previously_open_ip_list:
            if port in self.previously_open_ip_list[ip]:
                #if proto in self.previously_open_ip_list[ip][port]:
                for prev_packet in self.previously_open_ip_list[ip][port]:
                    if prev_packet.packet.haslayer(TCP) and prev_packet.packet.time- current_packet.packet.time < self.Recently_closed_port_timeout:
                        port_open=True
                        self.log_local_terminal_and_GUI_WARN(f"ip {ip} port {port} proto TCP was previously open",0)
        return port_open
    
    
    def is_ip_dst_on_local_network(self,ip_dst):
        if ip_dst in self.currently_open_ip_list:
            return True
        else:
            return False
        
    def is_ip_src_on_local_network(self,ip_src):
        if ip_src in self.currently_open_ip_list:
            return True
        else:
            return False
    
    def add_L2_reachable_host(self,ip,MAC,current_packet):
        if not self.is_ip_dst_on_local_network(ip):
            self.currently_open_ip_list[ip]={}
            self.log_local_terminal_and_GUI_WARN(f"ARP: Added add_L2_reachable_host {ip} based on num {current_packet.packet_num} {current_packet.packet}",4)
            #eel.insert_body(f"ARP: Added add_L2_reachable_host {ip} based on num {current_packet.packet_num} {current_packet.packet}")
            justification=f"Justification: Packet Number {current_packet.packet_num}  {current_packet.packet.payload}"
            if self.gui:
                eel.AddLocalIP(ip,justification)
            #self.gui_sock.send(f"ARP: Added add_L2_reachable_host {ip} based on num {current_packet.packet_num} {current_packet.packet}")
            
    def remove_L2_reachable_host(self,ip,MAC):
        if self.is_ip_dst_on_local_network(ip):
            #self.currently_open_ip_list.remove(ip)
            del self.currently_open_ip_list[ip]

    def Add_Packet_to_watch(self,current_packet):
        self.packet_watch_list.append(current_packet)
        '''
        for x in range(len(self.packet_watch_list) - 1, -1, -1):
            self.log_local_terminal_and_GUI_WARN(f"Current unanswered syn list {self.packet_watch_list[x].packet_num} {self.packet_watch_list[x].packet}")
        '''
    
    def Remove_Packet_from_watch(self,Matching_ACK):
        if "R" not in Matching_ACK.packet[TCP].flags:
            for x in range(len(self.packet_watch_list) - 1, -1, -1):
                historical_packet= self.packet_watch_list[x]
                if  historical_packet.packet[IP].src == Matching_ACK.packet[IP].dst and\
                    historical_packet.packet[IP].dst == Matching_ACK.packet[IP].src and\
                    historical_packet.packet[TCP].dport == Matching_ACK.packet[TCP].sport and\
                    historical_packet.packet[TCP].sport == Matching_ACK.packet[TCP].dport:
                    #TODO used to even match sequence numbers like below but that may be too strict
                    #historical_packet.packet[TCP].sport == Matching_ACK.packet[TCP].dport and \
                    #historical_packet.packet[TCP].seq == Matching_ACK.packet[TCP].ack -1:
                        #logging.warn(f"Removed answered SYN after {Matching_ACK.packet.time - self.packet_watch_list[x].packet.time} delay"+\
                        #             f"{Matching_ACK.packet} {Matching_ACK.packet.time} with {self.packet_watch_list[x].packet} {self.packet_watch_list[x].packet.time}")
                        self.log_local_terminal_and_GUI_WARN(f"Removed answered packet {self.packet_watch_list[x].packet_num} after {Matching_ACK.packet.time - self.packet_watch_list[x].packet.time} delay"+\
                                     f"{Matching_ACK.packet} {Matching_ACK.packet.time} with {self.packet_watch_list[x].packet} {self.packet_watch_list[x].packet.time}",2)
                        #print(Matching_ACK.packet.show(dump=True))
                        #print(self.packet_watch_list[x].packet.show(dump=True))
                        del self.packet_watch_list[x]
                    
    def Remove_ARP_from_watch(self,Matching_ARP):
        for x in range(len(self.ARP_requests) - 1, -1, -1):
            historical_ARP= self.ARP_requests[x]
            if  historical_ARP.packet[ARP].pdst == Matching_ARP.packet[ARP].psrc :
                    self.log_local_terminal_and_GUI_WARN(f"Removed answered ARP self.ARP_requests[x] {self.ARP_requests[x].packet} after {Matching_ARP.packet.time - self.ARP_requests[x].packet.time} delay"+\
                                 f" due to Matching_ARP.packet {Matching_ARP.packet} {Matching_ARP.packet.time} with {self.ARP_requests[x].packet} {self.ARP_requests[x].packet.time}",1)
                    self.log_local_terminal_and_GUI_WARN(f"Matching_ARP.packet[ARP].psrc {Matching_ARP.packet[ARP].psrc} Matching_ARP.packet[ARP].pdst {Matching_ARP.packet[ARP].pdst} self.ARP_requests[x].packet[ARP].psrc {self.ARP_requests[x].packet[ARP].psrc} self.ARP_requests[x].packet[ARP].pdst {self.ARP_requests[x].packet[ARP].pdst}",1)
                    #print(Matching_ACK.packet.show(dump=True))
                    #print(self.packet_watch_list[x].packet.show(dump=True))
                    del self.ARP_requests[x]
                    
    
    def Check_SYN_watch(self,current_packet):
        pass
    
    
    def Process_Incoming_SYN(self,current_packet):
        '''
        if self.is_port_open(current_packet.packet[IP].dst,current_packet.packet[TCP].dport,"TCP"):
            self.log_local_terminal_and_GUI_WARN(f"SYN to open port on dst {current_packet.packet_num} {current_packet.packet}")
            #TODO: Make sure that we synack the syn on a port we think is open, if not need to close the port
            pass
        else:
             #TODO: add SYN to dict with a timer
            self.Add_Packet_to_watch(current_packet)
            self.log_local_terminal_and_GUI_WARN(f"Add_Packet_to_watch for {current_packet.packet_num} {current_packet.packet}")
            #logging.warning(f" timestamp {current_packet.packet.time}")
            pass
        '''
        self.Add_Packet_to_watch(current_packet)
        self.log_local_terminal_and_GUI_WARN(f"Add_Packet_to_watch for {current_packet.packet_num} {current_packet.packet}",0)
        
    def Process_ACK(self,current_packet):
        #TODO: find the SYN and remove it before timer expires, if port closed mark as open
        self.Remove_Packet_from_watch(current_packet)
        self.open_port(current_packet.packet[IP].src,current_packet.packet[TCP].sport,"TCP",current_packet)
        
    def Process_Outgoing_TCP(self,current_packet):
        if "A" in current_packet.packet[TCP].flags:
            logging.info(f"Outgoing SA detected, so remove corresponding syn from list of unacked syns and process it as an open port{current_packet.packet}")
            self.Process_ACK(current_packet)
        elif "R" not in current_packet.packet[TCP].flags:
            #TODO:eventually we will log unwanted outbound traffic,
            self.open_port(current_packet.packet[IP].src,current_packet.packet[TCP].sport,"TCP",current_packet)
            logging.info(f"Outgoing Non R (non RST) packet, indicating that this port is open, so call to openport made for packet {current_packet.packet}")
            

        #TODO: Open ports due to outbound traffic that is non-RST
                    
    def Clear_unACKed_Packets(self,current_packet):
        while len(self.packet_watch_list):

            if current_packet.packet.time - self.packet_watch_list[0].packet.time > self.SYN_reply_timeout :
                self.log_local_terminal_and_GUI_WARN(f"### Unwanted Traffic ACK TIMEOUT: self.packet_watch_list was never acked, packet number :{self.packet_watch_list[0].packet_num} {self.packet_watch_list[0].packet}, close port should be called here",2)
                unwanted_packet=self.packet_watch_list.popleft()
                #self.report_unwanted.append(unwanted_packet)
                #print(f"CLEAR UNACKED SYNNNNNNNNNNNNNNNNNNNNNNN {type(unwanted_packet)} {type(unwanted_packet.packet)}")
                if "S" == current_packet.packet[TCP].flags:
                    confidence="High, unacked syn"
                    reason="SYN not acked"
                else:
                    confidence="TBD"
                    reason="TBD"
                self.Report_unwanted_traffic(unwanted_packet,reason,confidence)
                self.close_port(unwanted_packet.packet[IP].dst,unwanted_packet.packet[TCP].dport,"TCP",unwanted_packet)

                
            else:
                break
    
    def Clear_unreplied_ARPs(self,current_packet):
        while len(self.ARP_requests):
            if current_packet.packet.time - self.ARP_requests[0].packet.time >= self.ARP_reply_timeout :
                if self.is_ip_dst_on_local_network(self.ARP_requests[0].packet[ARP].pdst):
                    self.log_local_terminal_and_GUI_WARN(f"ARP: Remove ip {self.ARP_requests[0].packet[ARP].pdst} from local hosts  ARP TIMEOUT: self.ARP_requests was never replied to, packet number :{self.ARP_requests[0].packet_num} {self.ARP_requests[0].packet} ",4)
                    unwanted_packet=self.ARP_requests.popleft()
                    self.remove_L2_reachable_host(unwanted_packet.packet[ARP].pdst,"")
                    if self.gui:
                        eel.RemoveL2Host(unwanted_packet.packet[ARP].pdst)
                else:
                    self.log_local_terminal_and_GUI_WARN(f"ARP:would remove ip {self.ARP_requests[0].packet[ARP].pdst} but it's not in local hosts. TIMEOUT: self.ARP_requests was never replied to, packet number :{self.ARP_requests[0].packet_num} {self.ARP_requests[0].packet}, ",4)
                    self.ARP_requests.popleft()

            else:
                break
    
    def Process_TCP(self,current_packet):
        
        if current_packet.packet.haslayer(IP):
            if current_packet.packet.haslayer(TCP):
                self.Clear_unACKed_Packets(current_packet)
                if self.is_ip_dst_on_local_network(current_packet.packet[IP].dst):
                    self.num_total_tcp_packets=self.num_total_tcp_packets+1
                    if "S" == current_packet.packet[TCP].flags:
                        #logging.info(f"#################Has SYN {current_packet.packet}")
                        self.Process_Incoming_SYN(current_packet)
                    else:
                        if self.is_port_open(current_packet.packet[IP].dst,current_packet.packet[TCP].dport,"TCP"):
                            #Non syn traffic to an open port on our local network
                            #TODO: deep packet inspection for application layer unwanted traffic 
                            pass
                        else: # Non SYN traffic to a closed port on our local network
                        
                            if self.was_port_previously_open(current_packet) is True:
                                confidence="Low, socket was previously open for these ip/port/protocols"
                            
                            else:
                                confidence="High, no previous socket open for these ip/port/protocols"
                            
                            #self.Report_unwanted_traffic(current_packet,"Non SYN traffic to a closed port",confidence)
                            self.Add_Packet_to_watch(current_packet)
                            
                            #999999999999999999999999999999
                            #self.report_unwanted.append(current_packet)
                            #eel.AddUnwantedTraffic(current_packet.packet[IP].src,current_packet.packet[TCP].sport,current_packet.packet[IP].dst,current_packet.packet[TCP].dport,"TCP",current_packet.packet_num,str(current_packet.packet.load))
                            
                if self.is_ip_src_on_local_network(current_packet.packet[IP].src):
                    self.Process_Outgoing_TCP(current_packet)
            
        
    def hash_segment(self,segment, key):
        """
        Hash an IP segment (octet) with a key and return a consistent random value in [0, 255].
        """
        # Combine segment and key
        combined = f"{segment}-{key}"
        # Hash using SHA256
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        # Map to a number in the range 0-255
        return int(hashed[:2], 16) % 256

    def randomize_ip(self,ip_address):
        key="LightScope123!"
        """
        Randomize an IP address while maintaining format consistency.
        """
        try:
            ip = ipaddress.IPv4Address(ip_address)
            octets = str(ip).split('.')
            randomized_octets = [self.hash_segment(octet, key) for octet in octets]
            randomized_ip = ".".join(map(str, randomized_octets))
            return randomized_ip
        except ipaddress.AddressValueError:
            raise ValueError("Invalid IP address format.")
                   
    def Report_unwanted_traffic(self,current_packet,reason,confidence): 
        self.report_unwanted.append(current_packet)
        self.num_unwanted_tcp_packets=self.num_unwanted_tcp_packets+1
        if hasattr(current_packet.packet, 'load'):
            load=current_packet.packet.load
        else:
            load="no payload detected"
        if self.gui:
            eel.AddUnwantedTraffic(current_packet.packet[IP].src,current_packet.packet[TCP].sport,\
                                current_packet.packet[IP].dst,current_packet.packet[TCP].dport,\
                                "TCP",str(current_packet.packet[TCP].flags),current_packet.packet_num,str(load),\
                                reason,confidence)
        self.log_local_terminal_and_GUI_WARN(f"Report_unwanted_traffic {current_packet.packet.payload}, packet num {current_packet.packet_num} payload{load}",5)
        self.log_local_terminal_and_GUI_WARN(f"Unwanted traffic dump {current_packet.packet.show(dump=True)}",5)

        #cap max report_output_buffer size
        if len(self.report_output_buffer) > self.max_unwanted_buffer_size:
            del self.report_output_buffer[0]
        
        self.report_output_buffer.append(current_packet)
        self.log_local_terminal_and_GUI_WARN(f"Record added to self.report_output_buffer, which now has len {len(self.report_output_buffer)} and self.report_batch_length {self.report_batch_length}",4)

        if len(self.report_output_buffer) % self.report_batch_length ==0:
            try:
                self.Connect_and_report()

            except Exception as e:
                self.log_local_terminal_and_GUI_WARN(f"connection error to mysql {e}",5)
                


    def Connect_and_report(self):
        print(f"self.external_network_information {self.external_network_information}")
        mydb = mysql.connector.connect(
          host="3.130.64.19",
          #host="steel.ant.isi.edu",
          user="lightscope",
          password="lightscope",
          database="lightscope"
        )


        mycursor = mydb.cursor()


        while 0 <len(self.report_output_buffer):
            current_packet=self.report_output_buffer[0]

            sql = "INSERT INTO "+self.database +" (\
                system_time  ,\
                ip_version  ,\
                ip_ihl      ,\
                ip_tos      ,\
                ip_len      ,\
                ip_id       ,\
                ip_flags    ,\
                ip_frag     ,\
                ip_ttl      ,\
                ip_proto    ,\
                ip_chksum   ,\
                ip_src      ,\
                ip_dst_randomized,\
                ip_options  ,\
                tcp_sport   ,\
                tcp_dport   ,\
                tcp_seq     ,\
                tcp_ack     ,\
                tcp_dataofs ,\
                tcp_reserved,\
                tcp_flags   ,\
                tcp_window  ,\
                tcp_chksum  ,\
                tcp_urgptr  ,\
                ext_dst_ip_country  ,\
                ext_dst_ip_net_type  ,\
                ext_asn  ,\
                int_dst_ip_country  ,\
                int_dst_ip_net_type  ,\
                int_asn  ,\
                internal_ip_equals_external_ip  ,\
                internal_is_private  ,\
                external_is_private  ,\
                open_ports,\
                tcp_options \
            ) VALUES ( %s,%s, %s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s, %s,%s, %s, %s,%s,%s,%s, %s, %s,%s,%s,%s,%s, %s,%s,%s,%s,%s)"
            val = (\
                #system_time
                current_packet.packet.time,\
                #ip_version  ,\
                current_packet.packet[IP].version,\
                #ip_ihl      ,\
                current_packet.packet[IP].ihl,\
                #ip_tos      ,\
                current_packet.packet[IP].tos,\
                #ip_len      ,\
                current_packet.packet[IP].len,\
                #ip_id       ,\
                current_packet.packet[IP].id,\
                #ip_flags    ,\
                ','.join(str(v) for v in current_packet.packet[IP].flags),\
                #"test",\
                #ip_frag     ,\
                current_packet.packet[IP].frag,\
                #ip_ttl      ,\
                current_packet.packet[IP].ttl,\
                #ip_proto    ,\
                current_packet.packet[IP].proto,\
                #ip_chksum   ,\
                current_packet.packet[IP].chksum,\
                #ip_src      ,\
                current_packet.packet[IP].src,\
                #ip_dst_randomized      ,\
                self.randomize_ip(current_packet.packet[IP].dst),\
                #ip_options  ,\
                ','.join(str(v) for v in current_packet.packet[IP].options),\
                #"test",\
                #tcp_sport   ,\
                current_packet.packet[TCP].sport,\
                #tcp_dport   ,\
                current_packet.packet[TCP].dport,\
                #tcp_seq     ,\
                current_packet.packet[TCP].seq,\
                #tcp_ack     ,\
                current_packet.packet[TCP].ack,\
                #tcp_dataofs ,\
                current_packet.packet[TCP].dataofs,\
                #tcp_reserved,\
                current_packet.packet[TCP].reserved,\
                #tcp_flags   ,\
                ','.join(str(v) for v in current_packet.packet[TCP].flags),\
                #"test",\
                #tcp_window  ,\
                current_packet.packet[TCP].window,\
                #tcp_chksum  ,\
                current_packet.packet[TCP].chksum,\
                #tcp_urgptr  ,\
                current_packet.packet[TCP].urgptr,\
                #dst_ip_country  ,\
                #self.lookup_network_information (current_packet.packet[IP].dst)[0],\
                self.external_network_information[0],\
                #dst_ip_net_type  ,\
                #self.lookup_network_information (current_packet.packet[IP].dst)[1],\
                self.external_network_information[1],\
                #asn
                self.external_network_information[2],\

                self.internal_network_information[0],\
                #dst_ip_net_type  ,\
                #self.lookup_network_information (current_packet.packet[IP].dst)[1],\
                self.internal_network_information[1],\
                #asn
                self.internal_network_information[2],\
                
                self.internal_ip_equals_external_ip,\
                self.internal_is_private,\
                self.external_is_private,\
                #open_ports
                ','.join(str(v) for v in self.currently_open_ip_list[self.internal_ip]),\
                #tcp_options ,\ 
                ','.join(str(v) for v in current_packet.packet[TCP].options),\
                #"test",\
                )
            self.log_local_terminal_and_GUI_WARN(f"Record added to MYSQL DB {val}",4)
            mycursor.execute(sql, val)

            mydb.commit()
            del self.report_output_buffer[0]



        self.log_local_terminal_and_GUI_WARN("sql done?",3)
        







    def ARP_add_hosts(self,current_packet):
        #logging.info(f"AAAAAAAAAAAAAAA current_packet.packet[ARP] {current_packet.packet[ARP].show(dump=True)}")
        #logging.warning(f"AAAAAAAAAAAAAAA  {dir(current_packet.packet[ARP])}")
        #print(current_packet.packet[ARP].op)
        self.add_L2_reachable_host(current_packet.packet[ARP].psrc,current_packet.packet[ARP].hwsrc,current_packet)
        
    
    def ARP_add_request_watch(self,current_packet):
        #Track the ARP request, if it goes unanswered remove the requested host from L2 reachable
        #current_packet.packet[ARP].op == 2 means it was an ARP reply, ==1 is a request
        matching_out_of_order_reply=0
        self.ARP_same_timestamp.append(current_packet)
        if self.ARP_same_timestamp[0].packet.time != current_packet.packet.time:
            self.ARP_same_timestamp.clear()
            self.ARP_same_timestamp.append(current_packet)
        else:
            self.ARP_same_timestamp.append(current_packet)
        
        if current_packet.packet[ARP].op == 1:
            if self.ARP_same_timestamp:
                if self.ARP_same_timestamp[0].packet.time == current_packet.packet.time:
                    for ARP_with_same_timestamp in self.ARP_same_timestamp:
                        if  current_packet.packet[ARP].pdst == ARP_with_same_timestamp.packet[ARP].psrc :
                            matching_out_of_order_reply=1
                            self.log_local_terminal_and_GUI_WARN(f"Out of order ARP reply for num {current_packet.packet_num} {current_packet.packet} and {ARP_with_same_timestamp.packet_num} {ARP_with_same_timestamp.packet} ",1)  
                if not matching_out_of_order_reply:
                    self.ARP_requests.append(current_packet)
            
    
    def check_if_internal_ip_changed(self):
        current_internal_ip=self.get_internal_host_ip()
        if self.internal_ip !=current_internal_ip:
            self.internal_ip=current_internal_ip
            self.log_local_terminal_and_GUI_WARN(f"internal_ip updated {self.internal_ip}" ,6)

            if self.internal_ip not in self.currently_open_ip_list:
                self.currently_open_ip_list[self.internal_ip]={}

            self.update_internal_network_information(self.internal_ip)
            self.update_external_ip()

            if self.external_ip == self.internal_ip:
                self.internal_ip_equals_external_ip="True"
            else:
                self.internal_ip_equals_external_ip="False"

            self.internal_is_private=self.check_ip_is_private(self.internal_ip)

        return self.internal_ip



    def update_internal_ip(self,current_packet):
        if self.args.collection_ip == "self":
            if current_packet.packet_num % self.check_if_ip_changed_packet_interval ==0:
                self.check_if_internal_ip_changed()
    
    def get_internal_host_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to an external IP address (Google DNS) on port 80.
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip
    
    def get_interface_name(self,ip_address):
    # Iterate over all network interfaces and their addresses.
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == ip_address:
                    return interface
        return None
                    
    def Process_ARP(self,current_packet):
        #if collecting on all IPs use ARP method
        if self.args.collection_ip == "all":
            if current_packet.packet.haslayer(ARP):# 
                #Add the sender of the ARP request, we know they are there
                self.ARP_add_hosts(current_packet)
                self.ARP_add_request_watch(current_packet)
                #TODO: maybe change logic here to detect MAC issues with ip addresses and ARP, for now if it's responding/originating ARP then you can remove unreplied ARPs
                self.Clear_unreplied_ARPs(current_packet)
                self.Remove_ARP_from_watch(current_packet)
            
    
    def Shutdown_cleanup(self):
        count=0
        while len(self.packet_watch_list):
            confidence="Medium, shutdown called and these syns were unacked at the time of shutdown"
            self.Report_unwanted_traffic(self.packet_watch_list.popleft(),"Shutdown: SYN not acked",confidence)
            #self.report_unwanted.append(self.packet_watch_list.popleft())
            count=count+1
        #logging.warning(f"#################Cleared {count} unacked syns as part of shutdown ")
        self.log_local_terminal_and_GUI_WARN(f"Cleared {count} unacked syns as part of shutdown ",1)
        
        
    def Initial_ARP_calibration(self,current_packet):
        self.Process_ARP(current_packet)

                
    def Initial_TCP_calibration(self,current_packet):
        #add open ports deduced from mid-flow, i.e. if we are sending non R packets then the port is open
        if current_packet.packet.haslayer(IP):
            if current_packet.packet.haslayer(TCP):
                self.Process_Outgoing_TCP(current_packet)
        
        
        
    def Process_packet(self,current_packet):
        self.Process_ARP(current_packet)
        self.Process_TCP(current_packet)
        self.update_internal_ip(current_packet)

           
        
        
    
    def log_local_terminal_and_GUI_WARN(self,event_string,level):
        if level >= self.verbose:
            logging.warn(event_string)
            if self.gui:
                eel.LogEvent(event_string)





    


#LightScope will see these replies and think the port is open. Need to keep track in LightScope of which are real replies and which are us

class honeypot_fwd:

    def __init__(self,args):

        #self.INTERFACE = "eth0"  # Adjust if needed
        self.INTERFACE = args.interface  # Adjust if needed

        self.attacker_facing_forwarding_rules ={}
        self.honeypot_facing_forwarding_rules={}
        production_port="12345"
        honeypot_port="12345"
        production_ip="172.31.13.133"
        honeypot_ip="128.9.28.79"
        self.attacker_facing_forwarding_rules[production_ip+":"+production_port]= (honeypot_ip, honeypot_port)
        self.honeypot_facing_forwarding_rules[honeypot_ip+":"+honeypot_port]= production_ip

        production_port="8080"
        honeypot_port="80"
        production_ip="172.31.13.133"
        honeypot_ip="128.9.28.79"
        self.attacker_facing_forwarding_rules[production_ip+":"+production_port]= (honeypot_ip, honeypot_port)
        self.honeypot_facing_forwarding_rules[honeypot_ip+":"+honeypot_port]= production_ip
        self.nat_table_max_size=10

        self.attacker_facing_nat_table={}
        self.honeypot_facing_nat_table={}
        self.ring_buffer_helper=deque([])
        random_number = random.randint(1, 1000)
        self.min_eport=11000 + random_number
        self.max_eport=16000
        self.tmp_eport=self.min_eport



        

        self.sckt = conf.L3socket(iface=self.INTERFACE)

    def forward_packet(self,pkt):
        self.tmp_eport
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]
        
            # Check if it's traffic to the forwarder (i.e., SSH to 192.168.10.138:22)
            #if ip.dst == PRODUCTION_IP and tcp.dport == FORWARDER_PORT:
            #if ip.dst == PRODUCTION_IP and str(tcp.dport) in self.attacker_facing_forwarding_rules.keys():
            #if production IP and dest port in our honeypot forwarding rules
            from_attacker_key=str(ip.dst)+":"+str(tcp.dport)
            from_honeypot_key=str(ip.src)+":"+str(tcp.sport)
            print(f"*pck seen {pkt}")
            #print(f"*pckt recv from_attacker_key {from_attacker_key}, self.attacker_facing_forwarding_rules.keys() {self.attacker_facing_forwarding_rules.keys()}")
            if from_attacker_key in self.attacker_facing_forwarding_rules.keys():
                print(f"****Found {from_attacker_key} in self.attacker_facing_forwarding_rules.keys(), forwarding to honeypot")


                # Rewrite destination to 192.168.10.139:22

                attacker_facing_nat_key=str(ip.src)+":"+str(tcp.sport)
                #if we don't have an existing NAT rule
                if attacker_facing_nat_key not in self.attacker_facing_nat_table:
                    if  len(self.ring_buffer_helper) > self.nat_table_max_size:
                        delete_nat_key=self.ring_buffer_helper.pop()
                        delete_e_port=self.attacker_facing_nat_table[delete_nat_key]
                        del self.attacker_facing_nat_table[delete_nat_key]
                        del self.honeypot_facing_nat_table[delete_e_port]

                    self.ring_buffer_helper.appendleft(attacker_facing_nat_key)
                    self.attacker_facing_nat_table[attacker_facing_nat_key]=self.tmp_eport
                    self.honeypot_facing_nat_table[self.tmp_eport]=(ip.src,tcp.sport,tcp.dport)
                    print(f"****Adding NAT entry for ip.src {ip.src} tcp.sport {tcp.sport} self.tmp_eport {self.tmp_eport} tcp.dport {tcp.dport} lengths {len(self.attacker_facing_nat_table)} {len(self.honeypot_facing_nat_table)} ")
                    #print(self.attacker_facing_nat_table.keys())
                    self.tmp_eport=self.tmp_eport+1
                    if self.tmp_eport==self.max_eport:
                        self.tmp_eport=self.min_eport



                ephemeral_port=self.attacker_facing_nat_table[attacker_facing_nat_key]

                (HONEYPOT_IP, HONEYPOT_PORT)= self.attacker_facing_forwarding_rules[from_attacker_key]

                #print(f"********Forwarding traffic to HONEYPOT_IP {HONEYPOT_IP} HONEYPOT_PORT {HONEYPOT_PORT} from ephemeral_port {ephemeral_port}")

                #new_pkt = IP( dst=HONEYPOT_IP) / TCP(sport=int(ephemeral_port), dport= int(HONEYPOT_PORT),seq=tcp.seq, ack=tcp.ack, flags=tcp.flags, window=tcp.window) / tcp.payload
            


                octets = pkt[IP].src.split('.')
                first_octet = int(octets[0])   
                second_octet = int(octets[1])
                source_ip_octet_1AND2 = (first_octet << 8) | second_octet

                third_octet = int(octets[2])   
                fourth_octet = int(octets[3])
                source_ip_octet_3AND4 = (third_octet << 8) | fourth_octet
            
                tcp_layer=pkt[TCP]
                new_pkt = IP( dst=HONEYPOT_IP) /tcp_layer
                new_pkt[IP].id= source_ip_octet_1AND2
                new_pkt[TCP].urgptr=source_ip_octet_3AND4
                new_pkt[TCP].sport=int(ephemeral_port)
                new_pkt[TCP].dport= int(HONEYPOT_PORT)
                del new_pkt[IP].chksum
                del new_pkt[TCP].chksum

                #send(new_pkt, iface=INTERFACE,verbose=0)
                self.sckt.send(new_pkt)
                print(f"************outgoing packet to honeypot {new_pkt}")

            # Check if it's return traffic from honeypot
            #elif ip.src == HONEYPOT_IP : #  and tcp.sport == DESTINATION_PORT:
        
            elif from_honeypot_key in self.honeypot_facing_forwarding_rules.keys() : #  and tcp.sport == DESTINATION_PORT:
                print(f"****Found {from_honeypot_key} in self.honeypot_facing_forwarding_rules.keys(), forwarding to attckr")
                # Rewrite source to appear as if it's from forwarder IP:22
                print(f"self.honeypot_facing_nat_table.keys() {self.honeypot_facing_nat_table.keys()} looking for tcp.dport {tcp.dport} or tcp.sport {tcp.sport}")
                if tcp.dport in self.honeypot_facing_nat_table.keys():
                    (overwrite_IP_dst,overwrite_tcp_dport,overwrite_tcp_sport)=self.honeypot_facing_nat_table[tcp.dport]
                    overwrite_IP_src=self.honeypot_facing_forwarding_rules[from_honeypot_key]

                    #print(f"****pkt rec for tcp.dport {tcp.dport}, overwriting with overwrite_tcp_dport {overwrite_tcp_dport} and overwrite_sport {overwrite_sport} and overwrite_IP_dst{overwrite_IP_dst} overwrite_IP_src {overwrite_IP_src}")
                    #print(f"**** tcp.ack {tcp.ack} tcp.flags {tcp.flags}")

                    #new_pkt = IP(src=overwrite_IP_src, dst=overwrite_IP_dst) / TCP(sport=int(overwrite_sport), dport=int(overwrite_tcp_dport),seq=tcp.seq, ack=tcp.ack,  flags=tcp.flags, window=tcp.window) / tcp.payload

                    tcp_layer=pkt[TCP]
                    new_pkt = IP(src=overwrite_IP_src, dst=overwrite_IP_dst) /tcp_layer
                    #new_pkt[IP].src=overwrite_IP_src
                    #new_pkt[IP].dst=overwrite_IP_dst
                    new_pkt[TCP].sport=int(overwrite_tcp_sport)
                    new_pkt[TCP].dport=int(overwrite_tcp_dport)
                    del new_pkt[IP].chksum
                    del new_pkt[TCP].chksum

                
                
                    #send(new_pkt, iface=INTERFACE,verbose=0)
                    self.sckt.send(new_pkt)
                    print(f"************reply packet to attkr {new_pkt}")


    
    

