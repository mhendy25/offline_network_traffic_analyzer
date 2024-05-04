#!/usr/bin/env python3
import cmd
from read_packets import parse
import os
import re
import plotext as plt
import shutil
from hello import karaoke
from collections import Counter
import sys


class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()
        self.file = None 
        self.all_packets = [] # list of objects, each object contains the whole packet, and a summary (src/ dst IP and protocol)
        self.original_packets = []
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
        self.setup_environment()

        if len(sys.argv) > 1:
            file_name = sys.argv[1]
            if self.validate_file(file_name):
                self.do_read(file_name)
            else:
                print(f"Error: File '{file_name}' not found or invalid format.")
                sys.exit(1)
        else:
            print("No file provided. Type 'read <filename>' to load data.")
    
    def setup_environment(self):
        try:
            # Get the directory of the executable
            executable_dir = os.path.dirname(sys.executable)
            # Ensure the directory exists
            if os.path.exists(executable_dir):
                # Change the working directory
                os.chdir(executable_dir)
                logging.info(f"Changed working directory to {executable_dir}")
            else:
                logging.error(f"Executable directory does not exist: {executable_dir}")
        except Exception as e:
            logging.error(f"Failed to change directory: {e}")

            

    def default(self, line):
        print(f"\nUnknown command: {line} \nPlease use 'help' to see a list of commands\n")

    dog = """
                             ____________________________
                            /  _________________________ \\
                            | | C:\> ./sniffsift       | |
    ,-.___,-.               | |                        | |
    \_/_ _\_/               | | +_+ hello              | |
      )O_O(                 | | I've been alone with   | |
     { (_) } sniff! sniff!  | | you inside my mind ... | |
      `-^-'                 | |                        | |
                            | |________________________| |
                            \____________________________/
    """

    project_name = "sniffsift"

    dog = plt.colorize(dog, "red", "bold", "default", False)

    project_name = plt.colorize(project_name, "red", "bold", "default", False)

    prompt = "+_+ "
    intro =f"""
    {dog}
\nWelcome to {project_name}, an offline network traffic analyzer.
The input of the analyzer is a hexdump text file. 
Type `menu` to discover the features.
"""
    
    # intro = plt.colorize(intro, "black", "default", 136, False)

    # Your CLI commands and functionality will go here

    def do_hello(self, arg):
        """
        `hello`

        Karaoke!
        """
        
        karaoke()

        self.do_clear(None)


    def do_q(self, arg):
        '''
        `quit`

        Exit the CLI.
        '''
        return True
    
    def do_cd(self, arg):
        '''
        `cd <directory>`

        Change the current working directory to the specified path.
        '''
        if not arg:
            print("No directory provided. Usage: cd <directory>")
            return

        try:
            os.chdir(arg)
            print(f"Changed directory to {os.getcwd()}")
        except Exception as e:
            print(f"Error: {e}")
    
    def do_pwd(self, arg):
        '''
        `pwd`

        Print the current working directory.
        '''
        print(f"Current directory: {os.getcwd()}")
    

   
        # testing
        # print("Summary length =", len(pckt_lst))
        # print("summary[0] =", summary[0])
        
        for pckt in pckt_lst:

            if count <= 5:
                print("----------------------------------------------------------------")
                print(f"Packet {count}")

            packet_info = dict()

            packet_info["packet"] = pckt
        
            for subitem in pckt.summary:
                if count <= 5:
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
                
                # if pckt.timestamp is not None:
                #     packet_info["timestamp"] = pckt.timestamp
            self.all_packets.append(packet_info)
            count += 1

        print("----------------------------------------------------------------")
        print()
        print(f"Read and stored {len(self.all_packets)} packets.\n")
        if len(self.all_packets) > 5:
            print("Use `show {# of packets}` to show more packet summaries.\n")

        print("Use `menu` to show the menu\n\n")
        # self.do_show_menu(None)

#         print(f"""1. Filter the packets using `filter`
# You will be prompted to enter what to filter by.\n
# 2. Show protocol statistics using `distribution`\n
# 3. Show most active hosts using `top_talkers`\n
# \n """)
        
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

        Filter packets based on source/ destination parameters. Type "filter" to view each command and enter the desired source IP address, destination IP address, and protocol.
        '''
        # TODO: filter multiple in the same read
        # TODO: send the actual summary instead of the list of dicts 
        # Parse the filter string into a dictionary

        if not self.all_packets:
            print("\nNo packets to filter. Please read a file first.\n")
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
                protocol = input("Enter Protocol filter ('DNS', 'DHCP' or 'UDP'): ").strip().upper() or None
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
                        if min_size < 0:
                            print("\nInvalid minimum size. Please enter a non-negative whole number.\n")
                        else:
                            self.current_filters['min_size'] = min_size
                    except ValueError:
                        print("\nInvalid minimum size. Please enter a whole number.\n")
                        continue  
            elif choice == '9':
                max_size = input("Maximum packet size (bytes): ").strip()
                if max_size:
                    try:
                        max_size = int(max_size)
                        if max_size < 0:
                            print("\nInvalid maximum size. Please enter a non-negative whole number.\n")
                        else:
                            self.current_filters['max_size'] = max_size
                    except ValueError:
                        print("\nInvalid maximum size. Please enter a whole number.\n")
                        continue  
            elif choice == '0':
                break
            else:
                print("\nInvalid choice. Please try again.\n")

        # Apply the filters
        self.set_filter(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol,
                        src_port=src_port, dest_port=dest_port, min_size=min_size, max_size=max_size, src_mac=src_mac, dest_mac=dest_mac)
        #start_time=start_time, end_time=end_time
        # Feedback to the user
        if any([src_ip, dst_ip, protocol, src_port, dest_port, min_size, max_size, src_mac, dest_mac]):
            # print("\nFilters applied. Use 'display' to see filtered packets.\n\n")
            self.do_display(None)
        else:
            print("\nNo filters applied.\n")


    def do_clear_filter(self, arg):
        '''
        Clears Filters
        '''
        self.filtered_packets = {}
        self.last_filtered_packets = {}
        self.current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None, 'src_port': None, 'dest_port': None, 'min_size': None, 'max_size': None, 'src_mac': None, 'dest_mac': None}
        print("\nFilters cleared.\n")


        print("\nCleared filters successfully.\n")

        print("Use `menu` to show the menu\n\n")


    def do_display(self, arg):
        '''
        `display {number of packets}`

        Display filtered packets. Shows summary of packets after filters have been applied.
        Use `display` to display all filtered packets.
        '''

        filter_flag = all( item is None or  item == ""  for item in self.current_filters.values())
        
        if not filter_flag and not self.filtered_packets:
            print("\nFilters have been applied but no packets match the criteria. Please adjust the filters. Type `clear_filter` to clear the filter.\n")
            return
        elif filter_flag or not self.filtered_packets:
            print("\nNo filtered packets to display. Please apply filters first.\n")
            return
        if arg:
            if ( not arg.isdigit() ):
                print("\nEnter how many packets to display. \n eg: `display 5` to display the first 5 filtered packets.\n\n")
                return
            
            if (int(arg) > len(self.filtered_packets) or int(arg) < 1):
                print("\nPlease provide a number within the range of the packets filtered.\n\n")
                return
            
            pckt_num = int(arg)
        else:
            pckt_num = len(self.filtered_packets)
        
            
        
        count = 1
        print("\n\nDisplaying filtered packets:\n")
        print("----------------------------------------------------------------")
        for i in range(pckt_num):
        # for packet in self.filtered_packets:
            print(f"Packet {count}")
            print(str(self.filtered_packets[i]["packet"]))
            # print(str(packet["packet"]))
            print("----------------------------------------------------------------")
            count += 1
        print('\n')

        names = {
            'src_ip': 'Source IP',
            'dst_ip': 'Destination IP',
            'protocol': 'Protocol',
            'src_port': 'Source Port',
            'dest_port': 'Destination Port',
            'min_size': 'Minimum Packet Size',
            'max_size': 'Maximum Packet Size',
            'src_mac': 'Source MAC',
            'dest_mac': 'Destination MAC'
         }

        print("Current filters for packets:\n")
        for key, value in self.current_filters.items():
            if value is not None and value != "":
                print(f"{names.get(key, key)}: {value}\n")

        # print(f"Current filters for packets above\n")
        # for k, v in self.current_filters.items():
        #     if v is not None and v != "":
        #         print(f"{k}: {v}\n")
        
        print("Use `menu` to show the menu\n\n")
        # self.do_menu(None)
    

    def do_show(self, arg):
        '''
        `show {number of packets}`

        Command to show packets that have been read (non filtered output).
        Use `show` to show all packets.
        '''

        if not self.all_packets:
            print("\nNo packets to display. Please read a file first.\n")
            return
        
        if arg:
            if ( not arg.isdigit() ):
                print("Enter how many packets to show. \n eg: `show 5` to display the first 5 packets.\n\n")
                return
            
            if ( int(arg) > len(self.all_packets ) or int(arg) < 1):
                print("\nPlease provide a number within the range of the packets read.\n\n")
                return
            
            pckt_num = int(arg)
        else:
        # if arg is None:
            pckt_num = len(self.all_packets)
        # else:
            
        count = 1
        print("\n\nDisplaying packets:")
        print("----------------------------------------------------------------")
        for i in range(pckt_num):
        # for packet in self.all_packets:
            print(f"Packet {count}")
            print(str(self.all_packets[i]["packet"]))
            print("----------------------------------------------------------------")
            count += 1
        print('\n')

        print("Use `menu` to show the menu\n\n")
        

    def do_reset(self, arg):
        '''
        `reset`

        Erase all stored packet information
        '''
        self.file = None 
        self.all_packets = []
        self.last_filtered_packets = []
        self.current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None, 'src_port': None, 'dest_port': None, 'min_size': None, 'max_size': None, 'src_mac': None, 'dest_mac': None}
        self.filtered_packets = []

        print("\nErased all packets successfully.\n")

        print("Use `menu` to show the menu\n\n")


    def do_menu(self, arg):
        '''
        `menu`

        Display the functionalities of the program
        '''

        if not self.all_packets:
            instructions = """
1. To read a plain text hexdump file
    `read your_hexdump_file.txt`\n
2. To list files in your current directory
    `ls`\n
3. To clear the screen
    `clear`\n
4. For karaoke
    `hello`
    Turn the volume up ;-) \n
5. Type "help" to see all the available commands.\n
"""
        
        elif not self.filtered_packets:
            instructions = """
1. To filter the packets
    `filter`
    You will be prompted to enter what to filter by.\n
2. To clear the current filter
    `clear_filter`\n
3. To show protocol statistics
    `protodist`\n
4. To show packet arrival time statistics
    `delayviz`\n
5. To show most active hosts
    `top_talkers`\n
6. Type "help" to see all the available commands.\n
"""

# 6. To show the full packet use
#     `expand {packet #}`\n
# 7. To show packet summaries use
#     `show {# of packets}`\n
#     Use `show` to show all packets\n
# 8. To save all packets in a txt file use
#     `save`\n
#     Use `help save` for more options.\n
# 9. To delete all the packets use
#     `reset`\n
# 10. For karaoke use
#     `hello`
#     Turn the volume up ;-)\n

        else:
            instructions = """
1. To filter the packets
    `filter`
    You will be prompted to enter what to filter by.\n
2. To clear the current filter
    `clear_filter`\n
3. To display filtered packets
    `display {# of packets}`\n
4. To show the full filtered packet
    `expand {filtered packet #}`\n
5. To save the packets in a txt file
    `save`\n
    Use `help save` for more options.\n
6. To delete all the packets
    `reset`\n
7. Type "help" to see all the available commands.
"""

# 3. To show protocol statistics use
#     `protodist`\n
# 4. To show packet arrival time statistics use
#     `delayviz`\n
# 5. To show the most active hosts use
#     `top_talkers`\n
# 7. To show packet summaries (non filtered) use 
#     `show {# of packets}`\n
#     Use `show` to show all packets\n
# 10. For karaoke use
#     `hello`
#     Turn the volume up ;-)\n

        print(instructions)

        return


    def do_clear(self, arg):
        '''
        `clear`

        Clear the screen
        '''
        os.system('clear')

        self.do_menu(None)
        
        return
    
    
    def do_ls(self, arg):
        '''
        `ls`

        List contents of current directory
        '''
        excluded_files = {
            '__pycache__', 'myenv', 'build', 'dist', '.git', 'pyinstaller', 
            'python', 'pip', 'hello.py', 'lyrics.txt', 'hello.mp3', 
            'wireshark_export_packet_dissections.png', 'cli_tool.spec', '.DS_Store', '.gitignore'
        } 
        entries = os.listdir()  
        filtered_entries = [entry for entry in entries if entry not in excluded_files]
        for entry in filtered_entries:
            print(entry)
        print()


    def do_protodist(self, arg):
        '''
        `protodist`

        Shows the protocol distribution
        '''
        if not self.all_packets:
            print("\nNo packets to report on. Please read a file first.\n")
            return

        relevant_protocols = ['UDP', 'DNS', 'DHCP']
        protocol_counts = {protocol: 0 for protocol in relevant_protocols}
        
        for packet in self.all_packets:
            protocol = packet.get("protocol", "Unknown")
            if protocol in relevant_protocols:
                protocol_counts[protocol] += 1
        
        total_packets = sum(protocol_counts.values())
        if total_packets == 0:
            print("\nNo relevant packets found.\n")
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
        
        print("\n")
        plt.show()

        print("\nProtocol Distribution Summary:")
        for i, protocol in enumerate(labels):
            print(f"{protocol}: {sizes[i]} packets ({percentages[i]:.2f}%)")
        print(f"Total packets: {total_packets}\n")
        
        print("Use `menu` to show the menu\n")
    

    def do_delayviz(self, arg):
        '''
        `packet_distribution`

        Displays a time-series graph of the delay of packets' arrival time between to hosts  

        '''
        if not self.all_packets:
            print("No packets to report on. Please read a file first.")
            return
        
        print("Enter the source and destination IP addresses.\nPress enter to skip.")
        self.display_common_attributes('src_ip')
        src_ip = input("Source IP address: ").strip()
        self.display_common_attributes('dst_ip')
        dst_ip = input("Destination IP address: ").strip()
        arrival_times = []
        for i, pkt in enumerate(self.original_packets):
            # print(pkt.frame_info)
            layers = str(pkt.layers)
            if ("IP" in layers):
                if ("IPV6" in layers):
                    if pkt.ipv6.src == src_ip and pkt.ipv6.dst == dst_ip:
                        curr_stamp = pkt.sniff_timestamp
                        curr_stamp_float = float(pkt.sniff_timestamp)
                        arrival_times.append(curr_stamp_float)
                        print(f"\nPacket # {i} arrived at time: {plt.colorize(curr_stamp, 201, 'default', 158, False)}")
                else: # IPV4
                    if pkt.ip.src == src_ip and pkt.ip.dst == dst_ip:
                        curr_stamp = pkt.sniff_timestamp
                        curr_stamp_float = float(pkt.sniff_timestamp)
                        arrival_times.append(curr_stamp_float)
                        print(f"\nPacket # {i} arrived at time: {plt.colorize(curr_stamp, 201, 'default', 158, False)}")
            
        diff_times = []
        for i in range(len(arrival_times)-1):
            diff_times.append((arrival_times[i+1] - arrival_times[i])*1000)
        
        if len(diff_times) == 0:
            print("\nIncorrect IP addresses. Enter IP addresses that exchange packets.\nUse `help show` for some examples.\n")
            return

        print("\n\nThe time difference list: \n\n", diff_times)
        print("\n\n")
        plt.clf()
        plt.plot(diff_times, color='red+')
        plt.title("Packet Arrival Time Difference in Milliseconds")
        plt.xlabel("Packet #")
        plt.ylabel("Time Difference")
        # plt.colorize("integer color codes", 201, "default", 158, True)
        plt.show()
        print("\n Scroll up above the graph for additional information.\n")
        print(" Use `menu` to show the menu\n")


    def do_top_talkers(self, arg):
        '''
        `top_talkers`

        Shows the distribution of hosts sending packets
        '''
        if not self.all_packets:
            print("\nNo packets to filter. Please read a file first.\n")
            return
        
        unique_ips = dict()
        percentages = []
        
        # iterate over all the packets and extract the ip
        for pkt in self.all_packets:
            if pkt.get("ipv4_source", False) is not False:
                src = pkt['ipv4_source']
            else:
                src = pkt['ipv6_source']
        # store different ips in dict and count packets
            unique_ips[src] = unique_ips.get(src, 0) + 1

        for key, value in unique_ips.items():
            percentages.append( value/len(self.all_packets) * 100  )
        
        ips = list(unique_ips.keys())

        # str_percentages = [ str(percentage) for percentage in percentages]
        color_ips = [plt.colorize(ip, "black", "bold", "default", False) for ip in ips]
        # print(color_percentatages)

        # print(percentages)

        terminal_width = shutil.get_terminal_size().columns
        avail =  terminal_width - len(" Top Talkers % by IP ")
        line_char = "─"*(avail//2) + " Top Talkers % by IP " + "─"*(avail//2)

        # display the bars 
        print('\n')

        plt.colorize(line_char, "black", "bold", "default", True)
        print('')
        plt.simple_bar(color_ips, percentages, width = 100, color=88)
        
        plt.show()
        print('\n')

        print("Use `menu` to show the menu\n\n")
    

    def do_expand(self, arg):
        '''
        `expand {packet #}`

        Shows the full contents of the packet specified
        '''
        if not self.all_packets:
            print("\nNo packets to filter. Please read a file first.\n")
            return

        if not arg.isdigit():
            print("\nEnter which packet to expand. \n eg: `expand 5` to expand packet 5.\n") 
            return
        else:
            arg = int(arg) - 1
        
        if ( len(self.filtered_packets) > 0 ):
            if arg >= len(self.filtered_packets) or arg < 0:
                print("\nThere is no packet numbered {0}. Please provide a packet number within the range of the packets filtered.\n".format(arg+1))
                return
            else:
                print('\n')
                for l in self.filtered_packets[arg]["packet"].layers:
                    print(l)
        else:
            if arg >= len(self.all_packets) or arg < 0:
                print("\nThere is no packet numbered {0}. Please provide a packet number within the range of the packets read. \n".format(arg+1))
                return
            else:
                print('\n')
                for l in self.all_packets[arg]["packet"].layers:
                    print(l)

        print("Use `menu` to show the menu\n\n")


    def do_save(self, arg):
        '''
        `save {"filter"} {"full"}`
        
        Save the summary of the packets in a text file. 
        Use `save filter` to save the filtered packets only.
        Use `save full` to save all packets with all details
        Use `save filter full` to save full filtered packets
        '''
        if not self.all_packets:
            print("\nNo packets to filter. Please read a file first.\n")
            return
        
        pckts = self.all_packets

        if arg:
            options = arg.split()
            opt1 = options[0]
            if len(options) > 1:
                opt2 = options[1]
            else:
                opt2 = ""

            if (len(opt1) > 0) and opt1 != "filter" and opt1 != "full":
                print("\nInvalid option. Please specify 'filter' or 'full'.\n")
                return
            
            if (len(opt2) > 0) and opt2 != "filter" and opt2 != "full":
                print("\nInvalid option. Please specify 'filter' or 'full'.\n")
                return
        
            if opt1 == "filter" or opt2 == "filter":
                if not self.filtered_packets:
                    print("\nNo packets filtered. Please filter some packets first.\n")
                    return
                pckts = self.filtered_packets
        else:
            opt1 = ""
            opt2 = ""

        file_name = input("  > Enter the file name (no extension): ")

        if len(file_name) == 0:
            print("\nInvalid file name.\n")
            return
        
        with open("{}.txt".format(file_name), 'w') as file:
            # Write content to the file
            if opt1 == "full" or opt2 == "full":
                count = 1
                for pckt in pckts:
                    file.write(f"Packet {count}\n")
                    for layer in pckt["packet"].layers:
                        file.write(str(layer))
                        file.write("\n")
                    file.write("\n\n")
                    count += 1
            else:
                count = 1
                for pckt in pckts:
                    file.write(f"Packet {count}\n")
                    for line in pckt["packet"].summary:
                        file.write(line)
                        file.write("\n")
                    file.write("\n\n")
                    count += 1
        
        print("\nFile saved successfully.\n")

        print("\nUse `menu` to show the menu\n\n")


    def validate_file(self, file_name):
        '''
        validate file name and path.
        '''
        # error messages
        INVALID_FILETYPE_MSG = "\nError: Invalid file format. %s must be a .txt file.\n"
        INVALID_PATH_MSG = "\nError: Invalid file path/name. Path %s does not exist.\n"

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


if __name__ == "__main__":
    sniffsift().cmdloop()