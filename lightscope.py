import sys
from sys import platform
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
                    except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")
                else:
                    print(f"No Interface specified, capturing on the first available interfaces")
                    try:
                        sniff(prn=packet_handler,store =False)
                    except KeyboardInterrupt:
                        Port_status.Shutdown_cleanup()
                    except Exception as e:
                        print(f"Exception caught, {e}\n\ncontinuing")

            

    Port_status.Shutdown_cleanup()


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
#headless mode only
stop_event.clear()
capture_thread = Thread(target=start_live_capture, args=(args.interface,))
honeypot_forward_thread = Thread(target=start_live_honeypot_forward, args=(args,))
capture_thread.start()
