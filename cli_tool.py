#!/usr/bin/env python3
import cmd
from read_packets import parse
import os
import re
import plotext as plt
from collections import Counter
import sys


class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()
        self.file = None 
        self.all_packets = []
        self.last_filtered_packets = []
        self.current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None, 'src_port': None, 'dest_port': None, 'min_size': None, 'max_size': None, 'src_mac': None, 'dest_mac': None}
        self.filtered_packets = []
        self.src_ipv4_counter = Counter()
        self.dest_ipv4_counter = Counter()
        self.src_ipv6_counter = Counter()
        self.dest_ipv6_counter = Counter()
        self.src_port_counter = Counter()
        self.dest_port_counter = Counter()
        self.src_mac_counter = Counter()
        self.dest_mac_counter = Counter()

        if len(sys.argv) == 2:
            file_name = sys.argv[1]
            if self.validate_file(file_name):
                self.do_read(file_name)
            else:
                sys.exit(1)
        else:
            print("Please enter 1 .txt file. Usage: ./cli_tool.py <filename>")
            sys.exit(1)
            

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
                    self.src_mac_counter[packet_info['eth_source']] += 1
                    self.dest_mac_counter[packet_info['eth_dest']] += 1

                # Extracting IPv6 source and destination
                ipv6_match = re.search(ipv6_pattern, subitem)
                if ipv6_match:
                    ipv6_source = ipv6_match.group(1)
                    ipv6_dest = ipv6_match.group(2)
                    packet_info["ipv6_source"] = ipv6_source
                    packet_info["ipv6_dest"] = ipv6_dest
                    self.src_ipv6_counter[packet_info['ipv6_source']] += 1
                    self.dest_ipv6_counter[packet_info['ipv6_dest']] += 1


                # Extracting IPv4 source and destination
                ipv4_match = re.search(ipv4_pattern, subitem)
                if ipv4_match:
                    ipv4_source = ipv4_match.group(1)
                    ipv4_dest = ipv4_match.group(2)
                    packet_info["ipv4_source"] = ipv4_source
                    packet_info["ipv4_dest"] = ipv4_dest
                    self.src_ipv4_counter[packet_info['ipv4_source']] += 1
                    self.dest_ipv4_counter[packet_info['ipv4_dest']] += 1

                # Extracting UDP source and destination ports
                udp_match = re.search(udp_pattern, subitem)
                if udp_match:
                    udp_source_port = udp_match.group(1)
                    udp_dest_port = udp_match.group(2)
                    packet_info["udp_source_port"] = udp_source_port
                    packet_info["udp_dest_port"] = udp_dest_port
                    self.src_port_counter[packet_info['udp_source_port']] += 1
                    self.dest_port_counter[packet_info['udp_dest_port']] += 1
                
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
        # Filter by source IP
        if self.current_filters['src_ip']:
            src = packet.get("ipv4_source", packet.get("ipv6_source", None))
            if src != self.current_filters['src_ip']:
                return False

        # Filter by destination IP
        if self.current_filters['dst_ip']:
            dst = packet.get("ipv4_dest", packet.get("ipv6_dest", None))
            if dst != self.current_filters['dst_ip']:
                return False

        # Filter by protocol
        if self.current_filters['protocol']:
            if self.current_filters['protocol'].upper() not in packet.get("protocol", "").upper():
                return False

        # Filter by source port
        if self.current_filters['src_port']:
            src_port = packet.get("udp_source_port", packet.get("tcp_source_port", None))
            if src_port and src_port != self.current_filters['src_port']:
                return False

        # Filter by destination port
        if self.current_filters['dest_port']:
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

        # Filter by source MAC
        if self.current_filters['src_mac']:
            src = packet.get("eth_source", None)
            if src != self.current_filters['src_mac']:
                return False

        # Filter by destination MAC
        if self.current_filters['dest_mac']:
            dst = packet.get("eth_dest", None)
            if dst != self.current_filters['dest_mac']:
                return False

            


        return True

    def update_filtered_packets(self):
        self.filtered_packets = [packet for packet in self.all_packets if self.apply_filters(packet)]
        self.last_filtered_packets = self.filtered_packets

    def set_filter(self, src_ip=None, dst_ip=None, protocol=None, src_port=None, dest_port=None, start_time=None, end_time=None, min_size=None, max_size=None, src_mac=None, dest_mac=None):
        self.current_filters['src_ip'] = src_ip
        self.current_filters['dst_ip'] = dst_ip
        self.current_filters['protocol'] = protocol
        self.current_filters['src_port'] = src_port
        self.current_filters['dest_port'] = dest_port
        self.current_filters['min_size'] = min_size
        self.current_filters['max_size'] = max_size
        self.current_filters['src_mac'] = src_mac
        self.current_filters['dest_mac'] = dest_mac
        self.update_filtered_packets()

    #helper function to print out most common
    def display_common_attributes(self, attribute):
        if attribute == 'src_ip':
            print("Most common IPv4 source IPs:")
            max_length = max(len(ip) for ip, count in self.src_ipv4_counter.most_common(5))
            for ip, count in self.src_ipv4_counter.most_common(5):
                if ip is not None:
                    print(f"{ip:<{max_length}} : {count} times")

        elif attribute == 'dst_ip':
            print("Most common IPv4 destination IPs:")
            max_length = max(len(ip) for ip, count in self.dest_ipv4_counter.most_common(5))
            for ip, count in self.dest_ipv4_counter.most_common(5):
                if ip is not None:
                    print(f"{ip:<{max_length}} : {count} times")

        elif attribute == 'src_mac':
            print("Most common source MAC addresses:")
            max_length = max(len(mac) for mac, count in self.src_mac_counter.most_common(5))
            for mac, count in self.src_mac_counter.most_common(5):
                if mac is not None:
                    print(f"{mac:<{max_length}} : {count} times")

        elif attribute == 'dest_mac':
            print("Most common destination MAC addresses:")
            max_length = max(len(mac) for mac, count in self.dest_mac_counter.most_common(5))
            for mac, count in self.dest_mac_counter.most_common(5):
                if mac is not None:
                    print(f"{mac:<{max_length}} : {count} times")

        elif attribute == 'src_port':
            print("Most common source ports:")
            max_length = max(len(port) for port, count in self.src_port_counter.most_common(5))
            for port, count in self.src_port_counter.most_common(5):
                if port is not None:
                    print(f"{port:<{max_length}} : {count} times")

        elif attribute == 'dest_port':
            print("Most common destination ports:")
            max_length = max(len(port) for port, count in self.dest_port_counter.most_common(5))
            for port, count in self.dest_port_counter.most_common(5):
                if port is not None:
                    print(f"{port:<{max_length}} : {count} times")

        
    
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

        filter_options = {
            '1': 'Filter by Source IP',
            '2': 'Filter by Destination IP',
            '3': 'Filter by Source MAC Address',
            '4': 'Filter by Destination MAC Address',
            '5': 'Filter by Protocol',
            '6': 'Filter by Source Port',
            '7': 'Filter by Destination Port',
            '8': 'Filter by Minimum Packet Size',
            '9': 'Filter by Maximum Packet Size',
            '0': 'Apply Filters and Return'
        }
        src_ip = self.current_filters['src_ip']
        dst_ip = self.current_filters['dst_ip']
        protocol = self.current_filters['protocol']
        src_port = self.current_filters['src_port']
        dest_port = self.current_filters['dest_port']
        min_size = self.current_filters['min_size']
        max_size = self.current_filters['max_size']
        src_mac = self.current_filters['src_mac']
        dest_mac = self.current_filters['dest_mac']

        while True:
            print("\nSet your filters (choose a number):")
            for key, value in filter_options.items():
                print(f"{key}. {value}")

            choice = input("Enter your choice: ").strip()


            if choice == '1':
                self.display_common_attributes('src_ip')
                src_ip = input("Enter Source IP filter: ").strip() or None
                self.current_filters['src_ip'] = src_ip
            elif choice == '2':
                self.display_common_attributes('dst_ip')
                dst_ip = input("Enter Destination IP filter: ").strip() or None
                self.current_filters['dst_ip'] = dst_ip
            elif choice == '3':
                self.display_common_attributes('src_mac')
                src_mac = input("Enter Source MAC filter: ").strip() or None
                self.current_filters['src_mac'] = src_mac
            elif choice == '4':
                self.display_common_attributes('dest_mac')
                dest_mac = input("Enter Destination MAC filter: ").strip() or None
                self.current_filters['dest_mac'] = dest_mac
            elif choice == '5':
                protocol = input("Enter Protocol filter ('DNS' or 'DHCP'): ").strip().upper() or None
                self.current_filters['protocol'] = protocol
            elif choice == '6':
                self.display_common_attributes('src_port')
                src_port = input("Enter Source Port filter: ").strip() or None
                self.current_filters['src_port'] = src_port
            elif choice == '7':
                self.display_common_attributes('dest_port')
                dest_port = input("Enter Destination Port filter: ").strip() or None
                self.current_filters['dest_port'] = dest_port
            elif choice == '8':
                min_size = input("Minimum packet size (bytes): ").strip()
                if min_size:
                    try:
                        min_size = int(min_size)
                        self.current_filters['min_size'] = min_size
                    except ValueError:
                        print("Invalid minimum size. Please enter a whole number.")
                        continue  
            elif choice == '9':
                max_size = input("Maximum packet size (bytes): ").strip()
                if max_size:
                    try:
                        max_size = int(max_size)
                        self.current_filters['max_size'] = max_size
                    except ValueError:
                        print("Invalid maximum size. Please enter a whole number.")
                        continue  
            elif choice == '0':
                break
            else:
                print("Invalid choice. Please try again.")

        # Apply the filters
        self.set_filter(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol,
                        src_port=src_port, dest_port=dest_port, min_size=min_size, max_size=max_size, src_mac=src_mac, dest_mac=dest_mac)
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
        print("Filters cleared.")

    def do_display(self, arg):
        '''
        Display filtered packets. Shows details of packets after filters have been applied.
        '''

        if self.current_filters and not self.filtered_packets:
            print("Filters have been applied but no packets match the criteria. Please adjust the filters.")
            return
        elif not self.filtered_packets:
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
        
        labels = []
        sizes = []
        percentages = []  
        colors = ['blue'] * len(relevant_protocols)  # A list to store colors for each bar
        
        for protocol, count in protocol_counts.items():
            percentage = (count / total_packets) * 100
            percentages.append(percentage) 
            labels.append(protocol)
            sizes.append(count)
        
        plt.clf() 
    
        max_packets = max(sizes)
        step = max(1, max_packets // 5)  
        y_ticks = list(range(0, max_packets + step, step))
        
        plt.plot_size(100, 30)  
        plt.bar(labels, sizes, width=0.8) 
        plt.yticks(y_ticks)
        plt.xlabel("Protocols")
        plt.ylabel("Packets")
        plt.title("Protocol Distribution")
        
        plt.show()

        print("\nProtocol Distribution Summary:")
        for i, protocol in enumerate(labels):
            print(f"{protocol}: {sizes[i]} packets ({percentages[i]:.2f}%)")
        print(f"Total packets: {total_packets}\n")
        # if not self.all_packets:
        #     print("No packets to report on. Please read a file first.")
        #     return

        # relevant_protocols = ['UDP', 'DNS', 'DHCP']
        # protocol_counts = {protocol: 0 for protocol in relevant_protocols}

        # for packet in self.all_packets:
        #     protocol = packet.get("protocol", "Unknown")
        #     if protocol in relevant_protocols:
        #         protocol_counts[protocol] += 1

        # total_packets = sum(protocol_counts.values())
        # if total_packets == 0:
        #     print("No relevant packets found.")
        #     return
        
        # print("\nGraph Printed.")

        # print("\nProtocol Distribution:")
        # labels = []
        # sizes = []
        # explode = []  # this will be used to slightly separate the slices for better visibility
        # for protocol, count in protocol_counts.items():
        #     if count > 0:  # Only add to the pie chart if the count is greater than 0
        #         percentage = (count / total_packets) * 100
        #         print(f"{protocol}: {percentage:.2f}% ({count} packets)")
        #         labels.append(protocol)
        #         sizes.append(count)
        #         explode.append(0)  # adjust this value for more or less separation


        # def func(pct, allvals):
        #     absolute = int(pct/100.*np.sum(allvals))
        #     return "{:.1f}%\n({:d} pkts)".format(pct, absolute)

        # # Plotting the pie chart
        # fig, ax = plt.subplots()
        # wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=labels, autopct=lambda pct: func(pct, sizes),
        #                                 startangle=90)

        # for w in wedges:
        #     w.set_edgecolor('w')

        # for autotext in autotexts:
        #     autotext.set_color('white')

        # ax.axis('equal')  
        # plt.title('Protocol Distribution')
        
        # plt.legend(labels, title="Protocols", loc="best", bbox_to_anchor=(1, 0, 0.5, 1))

        # plt.tight_layout()  
        # plt.show(block=False)
        # print()
        

    def validate_file(self, file_name):
        '''
        validate file name and path.
        '''
        # error messages
        INVALID_FILETYPE_MSG = "Error: Invalid file format. %s must be a .txt file."
        INVALID_PATH_MSG = "Error: Invalid file path/ name. Path %s does not exist."

        if not self.valid_path(file_name):
            print(INVALID_PATH_MSG%(file_name))
            return False
        elif not self.valid_filetype(file_name):
            print(INVALID_FILETYPE_MSG%(file_name))
            return False
        return True
        

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

