import cmd
from read_packets import parse
import os
import re
import plotext as plt
import shutil


class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()
        self.file = None 
        self.all_packets = []
        self.last_filtered_packets = []
        self.current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None}
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
        if arg:
            file_name = arg
        else:
            file_name = ""
    
        # validate the file name/path
        if not self.validate_file(file_name):
            return

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
        # try:
        if self.current_filters['src_ip']:
            if packet.get("ipv4_source", False) != False:
                src = packet['ipv4_source']
            else:
                src = packet['ipv6_source']

            if src != self.current_filters['src_ip']:
                return False
            
        if self.current_filters['dst_ip']:

            if packet.get("ipv4_dest", False) != False:
                dst = packet['ipv4_dest']
            else:
                dst = packet['ipv6_dest']

            if dst != self.current_filters['dst_ip']:
                return False
        
        if self.current_filters['protocol']:
            if packet.get("protocol", False) != False:
                if self.current_filters['protocol'].upper() not in packet['protocol'].upper():
                    return False
        return True

    def update_filtered_packets(self):
        self.filtered_packets = [packet for packet in self.all_packets if self.apply_filters(packet)]
        self.last_filtered_packets = self.filtered_packets

    def set_filter(self, src_ip=None, dst_ip=None, protocol=None):
        self.current_filters['src_ip'] = src_ip
        self.current_filters['dst_ip'] = dst_ip
        self.current_filters['protocol'] = protocol
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

        # Apply the filters
        self.set_filter(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol)

        # Feedback to the user
        if any([src_ip, dst_ip, protocol]):
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
        `distribution`

        Shows the protocol distribution
        '''
        if not self.all_packets:
            print("No packets to report on. Please read a file first.")
            return
        protocol_counts = {}
        for packet in self.all_packets:
            protocol = packet.get("protocol", "Unknown")
            if protocol not in protocol_counts:
                protocol_counts[protocol] = 0
            protocol_counts[protocol] += 1

        total_packets = sum(protocol_counts.values())
        print("\nProtocol Distribution:")
        for protocol, count in protocol_counts.items():
            percentage = (count / total_packets) * 100
            print(f"{protocol}: {percentage:.2f}% ({count} packets)")
        print()
    

    def do_top_talkers(self, arg):
        '''
        `top_talkers`

        Shows the distribution of hosts sending packets
        '''
        if not self.all_packets:
            print("No packets to filter. Please read a file first.")
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
    
    def do_expand(self, arg):
        '''
        `expand {packet #}`

        Shows the full contents of the packet specified
        '''
        if not self.all_packets:
            print("No packets to filter. Please read a file first.")
            return

        arg = int(arg) - 1
        if arg < 0:
            print("Please provide a packet number within the range of the packets filtered.")
            return

        if len(self.filtered_packets) > 0:
            if arg >= len(self.filtered_packets):
                print("There is no packet numbered {0}. Please provide a packet number within the range of the packets filtered.".format(arg))
                return
            else:
                for l in self.filtered_packets[arg]["packet"].layers:
                    print(l)
        else:
            if int(arg) >= len(self.all_packets):
                print("There is no packet numbered {0}. Please provide a packet number within the range of the packets read.".format(arg))
                return
            else:
                for l in self.all_packets[arg]["packet"].layers:
                    print(l)

        

    def validate_file(self, file_name):
        '''
        validate file name and path.
        '''
        # error messages
        INVALID_FILETYPE_MSG = "Error: Invalid file format. %s must be a .txt file."
        INVALID_PATH_MSG = "Error: Invalid file path/name. Path %s does not exist."

        if not self.valid_path(file_name):
            print(INVALID_PATH_MSG%(file_name))
            return False
        elif not self.valid_filetype(file_name):
            print(INVALID_FILETYPE_MSG%(file_name))
            return False
        return True


    def valid_filetype(self, file_name):
        # validate file type
        return file_name.endswith('.txt')
 

    def valid_path(self, path):
        # validate file path
        return os.path.exists(path)

    


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

