import pyshark
from scapy.all import *

# we need to use the below function to convert hexa dump to pcap

def hexdump_to_pcap(hexdump_file, pcap_file):
    packets = []
    with open(hexdump_file, 'r') as f:
        for line in f:
            hex_data = line.strip().replace(' ', '')
            packet = bytes.fromhex(hex_data)
            packets.append(packet)

    # Write packets to pcap file
    wrpcap(pcap_file, packets)

    hexdump_file = "hexdump.txt"  
    pcap_file = "output.pcap"      
    hexdump_to_pcap(hexdump_file, pcap_file)

def process_ethernet_packets(pcap_file):
    capture = pyshark.FileCapture(pcap_file, only_summaries=False)

    for packet in capture:
        try:
            if 'Ethernet' in packet:
                src_mac = packet.eth.src
                dst_mac = packet.eth.dst
                eth_type = packet.eth.type

                # Output Ethernet basic header information
                print("Source MAC:", src_mac)
                print("Destination MAC:", dst_mac)
                print("Ethernet Type:", eth_type)
                print("---------------------------------------")

        except AttributeError:
            print('Encountered an error')
    # Close the capture file
    capture.close()

pcap_file = "example.pcap"

process_ethernet_packets(pcap_file)
