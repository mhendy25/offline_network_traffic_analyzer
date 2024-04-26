import cmd
import os
import re
import plotext as plt
from read_packets import parse  # Assuming you have a module named `read_packets` that contains the `parse` function


class sniffsift(cmd.Cmd):
    
    def __init__(self):
        super().__init__()
        self.file = None 
        self.all_packets = [] 
        self.original_packets = []
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
        file_name = arg
    
        # validate the file name/path
        self.validate_file(file_name)
        self.file = file_name
        
        # read and parse the file content
        pckt_lst, self.original_packets = parse(self.file)

        if len(pckt_lst) == 0:
            return

        count = 1
        for pckt in pckt_lst:
            src, dst, protocol = "Unknown", "Unknown", "Unknown"

            packet_info = dict()
            packet_info["packet"] = pckt
            
            for subitem in pckt.summary:
                # Regular expressions to extract source and destination addresses for IPv4 and IPv6
                ethernet_pattern = r"Ethernet II, Src: ([\w:]+), Dst: ([\w:]+)"
                ipv6_pattern = r"Internet Protocol Version 6, Src: ([\w:]+), Dst: ([\w:]+)"
                ipv4_pattern = r"Internet Protocol Version 4, Src: ([\d.]+), Dst: ([\d.]+)"
                udp_pattern = r"User Datagram Protocol, Src Port: (\d+), Dst Port: (\d+)"
                dns_pattern = r"Domain Name System (response|query)"

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
                dns_match = re.search(dns_pattern, subitem)
                if dns_match:
                    packet_info["protocol"] = "DNS"
                else:
                    packet_info["protocol"] = "UDP"

            self.all_packets.append(packet_info)
            count += 1

        print(f"Read and stored {len(self.all_packets)} packets.\n\n")

    def apply_filters(self, packet):
        if self.current_filters['src_ip']:
            if packet.get("ipv4_source", False):
                src = packet['ipv4_source']
            else:
                src = packet['ipv6_source']

            if src != self.current_filters['src_ip']:
                return False
            
        if self.current_filters['dst_ip']:
            if packet.get("ipv4_dest", False):
                dst = packet['ipv4_dest']
            else:
                dst = packet['ipv6_dest']

            if dst != self.current_filters['dst_ip']:
                return False
        
        if self.current_filters['protocol']:
            if packet.get("protocol", False):
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

        Filter packets based on source/ destination parameters.
        '''
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

    def do_distribution(self, arg):
        '''
        'distribution`

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

    def do_packet_distribution(self, arg):
        '''
        `packet_distribution`

        Displays a time-series graph of the delay of packets' arrival time between two hosts  

        '''
        if not self.all_packets:
            print("No packets to report on. Please read a file first.")
            return
        
        print("Enter the source and destination IP addresses:")
        src_ip = input("Source IP address: ").strip()
        dst_ip = input("Destination IP address: ").strip()
        
        dns_response_time = False
        if arg.strip().lower() == "xx":
            dns_response_time = True
        
        arrival_times = []
        prev_time = None
        first_time = None
        
        for i, pkt in enumerate(self.all_packets):
            try:
                if pkt["protocol"] == "DNS":
                    if dns_response_time:
                        curr_stamp = pkt["packet"].sniff_timestamp
                        curr_stamp_float = float(pkt["packet"].sniff_timestamp)

                        if not first_time:
                            first_time = curr_stamp_float
                        else:
                            arrival_times.append(curr_stamp_float - prev_time)
                            prev_time = curr_stamp_float
                    else:
                        layers = str(pkt["packet"].layers)
                        if ("IP" in layers):
                            if ("IPV6" in layers):
                                if pkt["ipv6_source"] == src_ip and pkt["ipv6_dest"] == dst_ip:
                                    curr_stamp = pkt["packet"].sniff_timestamp
                                    curr_stamp_float = float(pkt["packet"].sniff_timestamp)
                                    arrival_times.append(curr_stamp_float)
                            else: # IPV4
                                if pkt["ipv4_source"] == src_ip and pkt["ipv4_dest"] == dst_ip:
                                    curr_stamp = pkt["packet"].sniff_timestamp
                                    curr_stamp_float = float(pkt["packet"].sniff_timestamp)
                                    arrival_times.append(curr_stamp_float)
            except Exception as e:
                print(f"Error processing packet #{i}: {e}")

        diff_times = []
        for i in range(len(arrival_times)-1):
            diff_times.append((arrival_times[i+1] - arrival_times[i])*1000)

        print("The time difference list is:", diff_times)
        plt.plot(diff_times, color='red+')
        plt.title("Packet Arrival Time Difference in Milliseconds")
        plt.xlabel("Packet #")
        plt.ylabel("Time Difference")
        plt.show()

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


if __name__ == "__main__":
    sniffsift().cmdloop()
