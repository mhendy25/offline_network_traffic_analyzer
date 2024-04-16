import cmd
from read_packets import parse
import os
import re
import matplotlib.pyplot as plt
import numpy as np


class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()
        self.file = None 
        self.all_packets = []
        self.last_filtered_packets = []
        self.current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None, 'src_port': None, 'dest_port': None, 'start_time': None, 'end_time': None, 'min_size': None, 'max_size': None}
        self.filtered_packets = []

    def default(self, line):
        print(f"Unknown command: {line} \nPlease use 'help' to see a list of commands")

    prompt = "+_+ "
    intro = """\nWelcome to sniffsift, an offline network traffic analyzer.
The input of the analyzer is a hexdump text file.
Type "help" to see all the available commands. 
For information on how to use a command, type "help <command>"\n"""

    # Your CLI commands and functionality will go here

    def do_hello(self, line):
        """
        `hello`

        Print a greeting.
        """

        print("Hello, World!")


    def do_quit(self, line):
        '''
        `quit`

        Exit the CLI.
        '''
        return True
    

    def do_read(self, arg):
        '''
        `read your_hexdump_file.txt`

        The packets in the plaintext input hexdump file will be read and parsed.
        '''
        # get the file name/path
        file_name = arg
    
        # validate the file name/path
        self.validate_file(file_name)
        self.file = file_name
        count = 1
        # read and parse the file content
        
        pckt_lst = parse(self.file)

        if (len(pckt_lst) == 0):
            return

        # testing
        # print("Summary length =", len(pckt_lst))
        # print("summary[0] =", summary[0])
        
        for pckt in pckt_lst:
            print("----------------------------------------------------------------")
            print(f"Packet {count}")
            src, dst, protocol = "Unknown", "Unknown", "Unknown"

            packet_info = dict()

            packet_info["packet"] = pckt
            for subitem in pckt.summary:
                print(subitem)
                
                # Regular expressions to extract source and destination addresses for IPv4 and IPv6
                ethernet_pattern = r"Ethernet II, Src: ([\w:]+), Dst: ([\w:]+)"
                ipv6_pattern = r"Internet Protocol Version 6, Src: ([\w:]+), Dst: ([\w:]+)"
                ipv4_pattern = r"Internet Protocol Version 4, Src: ([\d.]+), Dst: ([\d.]+)"
                udp_pattern = r"User Datagram Protocol, Src Port: (\d+), Dst Port: (\d+)"

                # Extracting Ethernet source and destination
                eth_match = re.search(ethernet_pattern, subitem)
                if eth_match:
                    eth_source = eth_match.group(1)
                    eth_dest = eth_match.group(2)
                    packet_info["eth_source"] = eth_source
                    packet_info["eth_dest"] = eth_dest

                # Extracting IPv6 source and destination
                ipv6_match = re.search(ipv6_pattern, subitem)
                if ipv6_match:
                    ipv6_source = ipv6_match.group(1)
                    ipv6_dest = ipv6_match.group(2)
                    packet_info["ipv6_source"] = ipv6_source
                    packet_info["ipv6_dest"] = ipv6_dest

                # Extracting IPv4 source and destination
                ipv4_match = re.search(ipv4_pattern, subitem)
                if ipv4_match:
                    ipv4_source = ipv4_match.group(1)
                    ipv4_dest = ipv4_match.group(2)
                    packet_info["ipv4_source"] = ipv4_source
                    packet_info["ipv4_dest"] = ipv4_dest

                # Extracting UDP source and destination ports
                udp_match = re.search(udp_pattern, subitem)
                if udp_match:
                    udp_source_port = udp_match.group(1)
                    udp_dest_port = udp_match.group(2)
                    packet_info["udp_source_port"] = udp_source_port
                    packet_info["udp_dest_port"] = udp_dest_port
                
                # Extracting DNS/DHCP protocol
                dns_match = "Domain Name System" in subitem
                dhcp_match = "DHCP" in subitem
                if dns_match:
                    packet_info["protocol"] = "DNS"
                elif dhcp_match:
                    packet_info["protocol"] = "DHCP"
                else:
                    packet_info["protocol"] = "UDP"
                
                if pckt.size is not None:
                    packet_info["size"] = pckt.size
                
                if pckt.timestamp is not None:
                    packet_info["timestamp"] = pckt.timestamp
            print(self.all_packets)
            self.all_packets.append(packet_info)
            count += 1
        print("----------------------------------------------------------------")
        print()
        print(f"Read and stored {len(self.all_packets)} packets.\n\n")

        # testing
        # print("\n\n\n\n")
        # print(self.all_packets)
        # print("\n\n\n\n")

    def apply_filters(self, packet):
        print(packet)
        # Filter by source IP
        if self.current_filters['src_ip']:
            # Try to fetch IPv4 or IPv6 source, depending on what's available in the packet
            src = packet.get("ipv4_source", packet.get("ipv6_source", None))
            if src != self.current_filters['src_ip']:
                return False

        # Filter by destination IP
        if self.current_filters['dst_ip']:
            # Try to fetch IPv4 or IPv6 destination, depending on what's available in the packet
            dst = packet.get("ipv4_dest", packet.get("ipv6_dest", None))
            if dst != self.current_filters['dst_ip']:
                return False

        # Filter by protocol
        if self.current_filters['protocol']:
            # Check if the protocol is mentioned in the packet's protocol field
            if self.current_filters['protocol'].upper() not in packet.get("protocol", "").upper():
                return False

        # Filter by source port
        if self.current_filters['src_port']:
            # The source port can be named differently depending on the protocol, check both common fields
            src_port = packet.get("udp_source_port", packet.get("tcp_source_port", None))
            if src_port and src_port != self.current_filters['src_port']:
                return False

        # Filter by destination port
        if self.current_filters['dest_port']:
            # Similarly, check both UDP and TCP destination ports
            dest_port = packet.get("udp_dest_port", packet.get("tcp_dest_port", None))
            if dest_port and dest_port != self.current_filters['dest_port']:
                return False
        
        # Filter by packet size
        if self.current_filters['min_size'] or self.current_filters['max_size']:
            packet_size = packet.get("size")  
            if packet_size is None:
                return False  

            # Check minimum size condition, if set
            if self.current_filters['min_size'] and packet_size < self.current_filters['min_size']:
                return False

            # Check maximum size condition, if set
            if self.current_filters['max_size'] and packet_size > self.current_filters['max_size']:
                return False

        if self.current_filters['start_time'] or self.current_filters['end_time']:
            packet_timestamp = int(packet.get("timestamp", "0"))  # Assuming timestamp is already a string of digits
            start_timestamp = int(self.current_filters['start_time']) if self.current_filters['start_time'] else None
            end_timestamp = int(self.current_filters['end_time']) if self.current_filters['end_time'] else None

            # Check if the packet's timestamp is within the specified range
            if start_timestamp and packet_timestamp < start_timestamp:
                return False
            if end_timestamp and packet_timestamp > end_timestamp:
                return False        

        return True

    def update_filtered_packets(self):
        self.filtered_packets = [packet for packet in self.all_packets if self.apply_filters(packet)]
        self.last_filtered_packets = self.filtered_packets

    def set_filter(self, src_ip=None, dst_ip=None, protocol=None, src_port=None, dest_port=None, start_time=None, end_time=None, min_size=None, max_size=None):
        self.current_filters['src_ip'] = src_ip
        self.current_filters['dst_ip'] = dst_ip
        self.current_filters['protocol'] = protocol
        self.current_filters['src_port'] = src_port
        self.current_filters['dest_port'] = dest_port
        self.current_filters['min_size'] = min_size
        self.current_filters['max_size'] = max_size
        self.update_filtered_packets()
        
    
    def do_filter(self, arg):
        '''
        `filter`

        Filter packets based on the filter string. Please follow each command and enter the desired source IP address, destination IP address, and protocol
        '''
        # TODO: filter multiple in the same read
        # TODO: send the actual summary instead of the list of dicts 
        # Parse the filter string into a dictionary

        if not self.all_packets:
            print("No packets to filter. Please read a file first.")
            return

        print("Set your filters (press enter to skip):")

        src_ip = input("Source IP filter: ").strip() or None
        dst_ip = input("Destination IP filter: ").strip() or None
        protocol = input("Protocol filter ('DNS' or 'DHCP'): ").strip().upper() or None
        src_port = input("Source port filter: ").strip() or None
        dest_port = input("Destination port filter: ").strip() or None
        min_size = input("Minimum packet size (bytes): ").strip() or None

        if min_size is not None:
            try:
                min_size = int(min_size)
            except ValueError:
                print("Invalid minimum size.")
                return

        max_size = input("Maximum packet size (bytes): ").strip() or None

        if max_size is not None:
            try:
                max_size = int(max_size)
            except ValueError:
                print("Invalid maximum size.")
                return

        start_timestamp = input("Start timestamp: ").strip().lstrip('0') or None
        end_timestamp = input("End timestamp: ").strip().lstrip('0') or None

        if start_timestamp:
            start_timestamp = start_timestamp.zfill(9)
        if end_timestamp:
            end_timestamp = end_timestamp.zfill(9)

        # Apply the filters
        self.set_filter(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol,
                        src_port=src_port, dest_port=dest_port, start_time=start_timestamp, end_time=end_timestamp, min_size=min_size, max_size=max_size)
        #start_time=start_time, end_time=end_time
        # Feedback to the user
        if any([src_ip, dst_ip, protocol, src_port, dest_port, min_size, max_size]):
            print("Filters applied. Use 'display' to see filtered packets.\n\n")
        else:
            print("No filters applied.")


    def do_clear_filter(self,arg):
        '''
        Clears Filters
        '''
        self.filtered_packets = {}
        self.last_filtered_packets = {}

    def do_display(self, arg):
        '''
        Display filtered packets. Shows details of packets after filters have been applied.
        '''
        if not self.filtered_packets:
            print("No filtered packets to display. Please apply filters first.")
            return

        count = 1
        print("\n\nDisplaying filtered packets:\n")
        print("----------------------------------------------------------------")
        for packet in self.filtered_packets:
            print(f"Packet {count}")
            print(str(packet["packet"]))
            print("----------------------------------------------------------------")
            count += 1
        print('\n')
    
    def do_show_all(self, arg):
        '''
        Command to show all packets that have been read.
        '''

        if not self.all_packets:
            print("No packets to display. Please read a file first.")
            return

        
        count = 1
        print("\n\nDisplaying packets:")
        print("----------------------------------------------------------------")
        for packet in self.all_packets:
            print(f"Packet {count}")
            print(str(packet["packet"]))
            print("----------------------------------------------------------------")
            count += 1
        print('\n')

        # print("----------------------------------------------------------------")
        # for idx, packet in enumerate(self.all_packets, start=1):
        #     src = packet.get("src", "Unknown")
        #     dst = packet.get("dst", "Unknown")
        #     protocol = packet.get("protocol", "Unknown")
        #     # Add any other packet details you wish to display here

        #     print(f"Packet #{idx}:")
        #     print(f"  Source:      {src}")
        #     print(f"  Destination: {dst}")
        #     print(f"  Protocol:    {protocol}\n")
        #     print("----------------------------------------------------------------")


    def do_clear(self, arg):
        '''
        `clear`

        Clear the screen
        '''
        os.system('clear')
    
    
    def do_ls(self, arg):
        '''
        `ls`

        List contents of current directory
        '''
        os.system('ls')
        print()

    # def do_graph(self, flag):
    #     '''
    #     `graph {flag}`

    #     Visualize packet flows. Flag 0 for all packets, 1 for filtered packets.
    #     '''
    #     flag = flag.strip()
    #     if flag not in ['0', '1']:
    #         print("Invalid flag. Use 0 for all packets or 1 for filtered packets.")
    #         return

    #     packets_to_graph = self.last_filtered_packets if flag == '1' else self.all_packets

    #     if not packets_to_graph:
    #         print("No packets to display. Please ensure packets are loaded or filtered correctly.")
    #         return

    #     print("\n\nPacket Flows:")
    #     print("----------------------------------------------------------------")

    #     for idx, packet in enumerate(packets_to_graph, start=1):
    #         src = packet.get("src", "Unknown")
    #         dst = packet.get("dst", "Unknown")
    #         protocol = packet.get("protocol", "Unknown")

    #         # Creating a multi-line format for each packet
    #         print(f"Packet #{idx}:")
    #         print(f"  Source:      {src}")
    #         print(f"               |")
    #         print(f"               |  [{protocol}]")
    #         print(f"               V")
    #         print(f"  Destination: {dst}\n")
    #         print("----------------------------------------------------------------")
    
    def do_distribution(self, arg):
        '''
        'distribution`

        Shows the protocol distribution
        '''
        if not self.all_packets:
            print("No packets to report on. Please read a file first.")
            return

        relevant_protocols = ['UDP', 'DNS', 'DHCP']
        protocol_counts = {protocol: 0 for protocol in relevant_protocols}

        for packet in self.all_packets:
            protocol = packet.get("protocol", "Unknown")
            if protocol in relevant_protocols:
                protocol_counts[protocol] += 1

        total_packets = sum(protocol_counts.values())
        if total_packets == 0:
            print("No relevant packets found.")
            return
        
        print("\nGraph Printed.")

        print("\nProtocol Distribution:")
        labels = []
        sizes = []
        explode = []  # this will be used to slightly separate the slices for better visibility
        for protocol, count in protocol_counts.items():
            if count > 0:  # Only add to the pie chart if the count is greater than 0
                percentage = (count / total_packets) * 100
                print(f"{protocol}: {percentage:.2f}% ({count} packets)")
                labels.append(protocol)
                sizes.append(count)
                explode.append(0)  # adjust this value for more or less separation


        def func(pct, allvals):
            absolute = int(pct/100.*np.sum(allvals))
            return "{:.1f}%\n({:d} pkts)".format(pct, absolute)

        # Plotting the pie chart
        fig, ax = plt.subplots()
        wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=labels, autopct=lambda pct: func(pct, sizes),
                                        startangle=90)

        for w in wedges:
            w.set_edgecolor('w')

        for autotext in autotexts:
            autotext.set_color('white')

        ax.axis('equal')  
        plt.title('Protocol Distribution')
        
        plt.legend(labels, title="Protocols", loc="best", bbox_to_anchor=(1, 0, 0.5, 1))

        plt.tight_layout()  
        plt.show(block=False)
        print()
        

    def validate_file(self, file_name):
        '''
        validate file name and path.
        '''
        # error messages
        INVALID_FILETYPE_MSG = "Error: Invalid file format. %s must be a .txt file."
        INVALID_PATH_MSG = "Error: Invalid file path/ name. Path %s does not exist."

        if not self.valid_path(file_name):
            print(INVALID_PATH_MSG%(file_name))
        elif not self.valid_filetype(file_name):
            print(INVALID_FILETYPE_MSG%(file_name))
        

    def valid_path(self, path):
        # validate file path
        return os.path.exists(path)
    
    
    def valid_filetype(self, file_name):
        # validate file type
        return file_name.endswith('.txt')

    # def precmd(self, line):
    #     # Add custom code here
    #     print("Before command execution")
    #     return line  # You must return the modified or original command line
    

    # def postcmd(self, stop, line):
    #     # Add custom code here
    #     print()
    #     return stop  # Return 'stop' to control whether the CLI continues or exits
    

    # def preloop(self):
    #     # Add custom initialization here
    #     print("Initialization before the CLI loop")
    

    # def postloop(self):
    #     # Add custom cleanup or finalization here
    #     print("Finalization after the CLI loop")



if __name__ == "__main__":
    sniffsift().cmdloop()

