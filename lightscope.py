# python lightscope.py --interface "Ethernet"

import sys
from sys import platform

# if (platform == 'darwin'):
#     # if system is mac, then patch eel to prevent error
#     from mac_patch import *
#     modify_eel_init()

import datetime
from lightscope_core import *
from scapy.all import *
try:
    from pylibpcap.base import Sniff
    from pylibpcap import get_first_iface

except:
    pass
import datetime
from threading import Thread, Event
import os

import argparse
import configparser
import json



def post_run_analysis(Port_status):
    Port_status.log_local_terminal_and_GUI_WARN(f'********************************************************************',6)
    Port_status.log_local_terminal_and_GUI_WARN(f'****Packet capture terminated at {datetime.datetime.now()} and ran for {datetime.datetime.now() - timenow}****',6)
    Port_status.log_local_terminal_and_GUI_WARN(f'********************************************************************',6)
    print("Begin post_run_analysis")
    unwanted_ip_src=[]
    unwanted_ip_dst=[]
    unwanted_tcp_sport=[]
    unwanted_tcp_dport=[]
    unwanted_flags=[]
    unwanted_payload_len=[]
    unwanted_packet_num=[]
    unwanted_payload=[]

    print(f"We have {len(Port_status.report_unwanted)} unwanted packets found\n") 
    for x in Port_status.report_unwanted:
        unwanted_ip_src.append(x.packet[IP].src)
        unwanted_ip_dst.append(x.packet[IP].dst)
        unwanted_tcp_sport.append(x.packet[TCP].sport)
        unwanted_tcp_dport.append(x.packet[TCP].dport)
        unwanted_flags.append(x.packet[TCP].flags)
        #print( binascii.hexlify(str(x.packet[TCP].payload.show(dump=True))))
        # print( x.packet[TCP].payload.show(dump=True))
        # print( x.packet[TCP].payload.show())
         
        unwanted_packet_num.append(x.packet_num)
        unwanted_payload.append(x.packet[TCP].payload.show())

    Unwanted_df=pd.DataFrame(
        {'unwanted_ip_src': unwanted_ip_src,
         'unwanted_ip_dst': unwanted_ip_dst,
         'unwanted_tcp_sport': unwanted_tcp_sport,
         'unwanted_tcp_dport': unwanted_tcp_dport,
         'unwanted_flags': unwanted_flags,
         'unwanted_packet_num': unwanted_packet_num,
         'unwanted_payload': unwanted_payload
        })

    
    #print(f"Unwanted_df.describe()\n {Unwanted_df.describe()}\n\n")
    print(f"Unwanted_df['unwanted_ip_src'].value_counts()\n{Unwanted_df['unwanted_ip_src'].value_counts()}\n\n")
    print(f"Unwanted_df['unwanted_ip_dst'].value_counts()\n{Unwanted_df['unwanted_ip_dst'].value_counts()}\n\n")
    #print(f"Unwanted_df['unwanted_tcp_sport'].value_counts()\n{Unwanted_df['unwanted_tcp_sport'].value_counts()}\n\n")
    #print(f"Unwanted_df['unwanted_tcp_dport'].value_counts()\n{Unwanted_df['unwanted_tcp_dport'].value_counts()}\n\n")
    print(f"Unwanted_df['unwanted_flags'].value_counts()\n{Unwanted_df['unwanted_flags'].value_counts()}\n\n")
    print(f"Unwanted_df['unwanted_payload'].value_counts()\n{Unwanted_df['unwanted_payload'].value_counts()}\n\n")
    print(f"Unwanted_df.head()\n {Unwanted_df.head(50)}\n\n")

    print(f"Unwanted_df.loc[Unwanted_df['unwanted_ip_src'] == '192.168.10.132']\n{Unwanted_df.loc[Unwanted_df['unwanted_ip_src'] == '192.168.10.132']}")
    

    print(f"*********** \n\n Ports Open and Hosts Discovered \n\n **********************")

    sorted_currently_open_ip_list = list(Port_status.currently_open_ip_list.keys())
    sorted_currently_open_ip_list.sort()

    for openIP in   sorted_currently_open_ip_list:
        print("############################################")
        print(openIP)
        #sock.send(openIP)
        sorted_port_list = list(Port_status.currently_open_ip_list[openIP].keys())
        sorted_port_list.sort()
        print(f" {len(sorted_port_list)} Open ports")
        if len(sorted_port_list) < 20:
            for openPort in sorted_port_list:
                print(f"Open port: {openPort}") 
                for index in range(len(Port_status.currently_open_ip_list[openIP][openPort])):
                    print(f"Protocol:{Port_status.currently_open_ip_list[openIP][openPort][index].proto}  Triggering Packet: {Port_status.currently_open_ip_list[openIP][openPort][index].packet.packet_num} {Port_status.currently_open_ip_list[openIP][openPort][index].packet.packet} \n") 
        else:
            print(f" \n## Tons of open ports \n##")
    '''                           
    for x in Port_status.report_unwanted:
        print(f"{x.packet.payload} {x.packet_num} {x.packet.show(dump=True)}")
    '''
        
    print(f"*********** \n\n Ports open but closed later \n\n **********************")    
    sorted_currently_closed_ip_list = list(Port_status.previously_open_ip_list.keys())
    sorted_currently_closed_ip_list.sort()

    for openIP in   sorted_currently_closed_ip_list:
        print("################CLOSED############################")
        print(openIP)
        #sock.send(openIP)
        sorted_port_list = list(Port_status.previously_open_ip_list[openIP].keys())
        sorted_port_list.sort()
        print(f" {len(sorted_port_list)} Previously open ports")
        if len(sorted_port_list) < 20:
            for openPort in sorted_port_list:
                print(f"Open port: {openPort}") 
                for index in range(len(Port_status.previously_open_ip_list[openIP][openPort])):
                    print(f"Protocol:{Port_status.previously_open_ip_list[openIP][openPort][index]} \n") 
        else:
            print(f" \n## Tons of open ports \n##")
        
        

def ensure_directory(directory_name):
    """Ensure the directory exists, and if not, create it."""
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)
        # print(f"Directory '{directory_name}' created.")

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
 
    return os.path.join(base_path, relative_path)

def generate_pcap_filepath():
    # Get current date and time
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y%m%d-%H%M%S")
    ensure_directory("./live-pcap-record")
    filepath = f"./live-pcap-record/pcap-{timestamp}.pcap"
    return filepath

def packet_handler(packet):
    global packet_buf
    global Port_status
    global packet_number
    if stop_event.is_set():
        raise KeyboardInterrupt
    
    packet_buf.append(packet)
    if(len(packet_buf)>=100):
        with open(filepath, 'ab') as f:
            wrpcap(f,packet_buf, append = True)
        packet_buf = []
        
    packet_to_add = packet[Ether]
    wrapped_packet_to_add=Packet_Wrapper(packet_to_add,packet_number)
    Port_status.Process_packet(wrapped_packet_to_add)
    packet_number=packet_number+1


def read_from_file():

    myreader = PcapReader(args.readfile)
    packet_number = 0
    Port_status=Ports()
    for packet_to_add in myreader:
        wrapped_packet_to_add=Packet_Wrapper(packet_to_add,packet_number)
        Port_status.Process_packet(wrapped_packet_to_add)
        packet_number=packet_number+1
    Port_status.Shutdown_cleanup()   


def start_live_capture(interface):
    global packet_number
    global packet_buf
    global Port_status
    global filepath
    filepath = generate_pcap_filepath()
    packet_number = 0
    Port_status=Ports(args)
    
    internal_ip=Port_status.get_internal_host_ip()
    #print(internal_ip)
    interface=Port_status.get_interface_name(internal_ip)
    print(f"collecting on interface {interface}")
    #Port_status.update_external_ip()
    print(f"To view your logs, please visit XXXXXXXXXXXXXXXXXXXXXXXXXXX todo for report")

        

    print(f"Platform {platform} detected")
    if(platform == 'linux'):

        sniffobj = None
        try:
            if interface:
                #print(f"Capturing on interface {interface}")
                if args.pcap:
                    try:
                        sniffobj = Sniff(interface, count=-1, promisc=1, out_file=filepath)
                    except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")
                else:
                    try:
                        sniffobj = Sniff(interface, count=-1, promisc=1)
                    except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")
            else:
                interface=conf.iface
                # interface=get_first_iface()
                #print(f"Capturing on interface {interface}")
                if args.pcap:
                    try:
                        sniffobj = Sniff(interface, count=-1, promisc=1, out_file=filepath)
                    except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")
                else:
                    try:
                        sniffobj = Sniff(interface, count=-1, promisc=1)
                    except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")

            for plen, t, buf in sniffobj.capture():
                if stop_event.is_set():
                    break
                packet_to_add = scapy.layers.l2.Ether(buf)
                wrapped_packet_to_add=Packet_Wrapper(packet_to_add,packet_number)
                Port_status.Process_packet(wrapped_packet_to_add)
                packet_number=packet_number+1
        finally:
            if sniffobj is not None:
                stats = sniffobj.stats()

    elif(platform =='darwin'):
        sniffobj = None
        try:
            interface = conf.iface.name
            #print(f"Capturing on interface {interface}")
            if args.pcap:
                try:
                    sniffobj = Sniff(interface, count=-1, promisc=1, out_file=filepath)
                except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")
            else:
                try:
                    sniffobj = Sniff(interface, count=-1, promisc=1)
                except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")
            for plen, t, buf in sniffobj.capture():
                if stop_event.is_set():
                    break
                packet_to_add = scapy.layers.l2.Ether(buf)
                wrapped_packet_to_add=Packet_Wrapper(packet_to_add,packet_number)
                Port_status.Process_packet(wrapped_packet_to_add)
                packet_number=packet_number+1 
        finally:
            if sniffobj is not None:
                stats = sniffobj.stats()
    else:
        # when system is windows
        # create empty pcap file
        if args.pcap:
            with open(filepath,'wb') as f:
                wrpcap(f,[],append=False)   
            while True:
                try:
                    if interface:
                        #print(f"Capturing on interface {interface}")
                        try:
                            sniff(iface=interface,prn=packet_handler,store =False)
                        except Exception as e:
                            print(f"Exception caught, {e}\n\ncontinuing")
                        
                    else:
                        print(f"No Interface specified, capturing on the first available interface")
                        try:
                            sniff(prn=packet_handler,store =False)
                        except Exception as e:
                            print(f"Exception caught, {e}\n\ncontinuing")
                except KeyboardInterrupt:
                    Port_status.Shutdown_cleanup()
                    post_run_analysis(Port_status)
                except Exception as error:
                    print("An error occurred:", error)
                finally:
                    if packet_buf:
                        with open(filepath, 'ab') as f:
                            wrpcap(f,packet_buf, append = True)
                        packet_buf=True
        else:
            while True:
                if interface:
                    #print(f"Capturing on interface {interface}")
                    # interface = 'Wi-Fi 2'
                    # print('here there and everywhere')
                    try:
                        sniff(iface=interface,prn=packet_handler,store =False)
                    except KeyboardInterrupt:
                        Port_status.Shutdown_cleanup()
                        post_run_analysis(Port_status)
                    except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")
                else:
                    print(f"No Interface specified, capturing on the first available interfaces")
                    try:
                        sniff(prn=packet_handler,store =False)
                    except KeyboardInterrupt:
                        Port_status.Shutdown_cleanup()
                        post_run_analysis(Port_status)
                    except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")

            

    Port_status.Shutdown_cleanup()
    post_run_analysis(Port_status)


class config_arguments:
    def __init__(self, config_file='config.ini'):
        # Default values
        self.interface = False
        self.gui = False
        self.verbose = 6
        self.pcap = False
        self.database = False
        self.readfile = ""
        self.collection_ip=""
        self.ports_to_forward=[]
        
        # Load values from the config file.
        self.load_config(config_file)
    
    def load_config(self, config_file):
        config = configparser.ConfigParser()
        config.read(config_file)
        
        # Assuming all configuration is under the [Settings] section.
        if 'Settings' in config:
            self.verbose = config.getint('Settings', 'verbose', fallback=self.verbose)
            self.database = config.get('Settings', 'database', fallback=self.database).lower()
            self.collection_ip=config.get('Settings', 'collection_ip', fallback="all").lower()
            self.ports_to_forward=config.get('Settings', 'ports_to_forward', fallback=[])



        else:
            print("Warning: 'Settings' section not found in the config file.")

    def __str__(self):
        return (f"GUI mode enabled: {self.gui}\n"
                f"Verbose level: {self.verbose} (6 is silent, 5 is unwanted traffic only, "
                f"4 includes local hosts discovered, 3 includes ports opened and closed, ... 0 is everything)\n"
                f"Saving traffic to local pcap? {self.pcap}\n"
                f"Remote database selected? {self.database}\n"
                f"Read File selected? {self.readfile}\n"
                f"Interface {self.interface}\n"
                f"Forwarding ports {self.ports_to_forward} to honeypot \n"
                f"Collecting from IPs {self.collection_ip}\n")


############# MAIN ########################


args = config_arguments('config.ini')
print(str(config_arguments('config.ini')))

def start_live_honeypot_forward(args):
    forwarder=honeypot_fwd(args)
    INTERFACE = forwarder.INTERFACE
    sniff(
        iface=INTERFACE,

        prn=forwarder.forward_packet,
        store=0
    )


timenow=datetime.datetime.now()


stop_event = Event()
packet_buf = []

#headless mode
stop_event.clear()
capture_thread = Thread(target=start_live_capture, args=(args.interface,))
honeypot_forward_thread = Thread(target=start_live_honeypot_forward, args=(args,))
capture_thread.start()
