import cmd
from read_packets import parse
import os
import re
import plotext as plt
import shutil
from hello import karaoke

class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()
        self.file = None 
        self.all_packets = [] # list of objects, each object contains the whole packet, and a summary (src/ dst IP and protocol)
        self.original_packets = []
        self.last_filtered_packets = []
        self.current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None}
        self.filtered_packets = []

    def default(self, line):
        print(f"Unknown command: {line} \nPlease use 'help' to see a list of commands")

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


    def do_quit(self, arg):
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
        
        pckt_lst, self.original_packets = parse(self.file)

        if (len(pckt_lst) == 0):
            return

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

        Filter packets based on source/ destination parameters. Type "filter" to view each command and enter the desired source IP address, destination IP address, and protocol.
        '''
        # TODO: filter multiple in the same read
        # TODO: send the actual summary instead of the list of dicts 
        # Parse the filter string into a dictionary

        if not self.all_packets:
            print("\nNo packets to filter. Please read a file first.\n")
            return

        print("Set your filters (press enter to skip):")

        src_ip = input("Source IP filter: ").strip() or None
        dst_ip = input("Destination IP filter: ").strip() or None
        protocol = input("Protocol filter ('DNS' or 'DHCP'): ").strip().upper() or None

        # Apply the filters
        self.set_filter(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol)

        # Feedback to the user
        if any([src_ip, dst_ip, protocol]):
            print("\nFilters applied. Use 'display' to see filtered packets.\n\n")
        else:
            print("\nNo filters applied.\n")


    def do_clear_filter(self, arg):
        '''
        Clears Filters
        '''
        self.filtered_packets = {}
        self.last_filtered_packets = {}

        print("\nCleared filters successfully.\n")

        print("Use `menu` to show the menu\n\n")


    def do_display(self, arg):
        '''
        `display {number of packets}`

        Display filtered packets. Shows summary of packets after filters have been applied.
        Use `display` to display all filtered packets.
        '''
        if not self.filtered_packets:
            print("\nNo filtered packets to display. Please apply filters first.\n\n")
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
        self.current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None}
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
Type "help" to see all the available commands. For information 
on how to use a command, type "help <command>"\n
1. To read a plain text hexdump file use
    `read your_hexdump_file.txt`\n
2. To list files in your current directory use
    `ls`\n
3. To clear the screen use
    `clear`\n
4. For karaoke use
    `hello`
    Turn the volume up ;-) \n"""
        
        elif not self.filtered_packets:
            instructions = """
Type "help" to see all the available commands. For information 
on how to use a command, type "help <command>"\n
1. To filter the packets use
    `filter`
    You will be prompted to enter what to filter by.\n
2. To clear the current filter use
    `clear_filter`\n
3. To show protocol statistics use
    `distribution`\n
4. To show packet arrival time statistics use
    `delayviz`\n
5. To show most active hosts use
    `top_talkers`\n
6. To show the full packet use
    `expand {packet #}`\n
7. To show packet summaries use
    `show {# of packets}`\n
    Use `show` to show all packets\n
8. To save all packets in a txt file use
    `save`\n
    Use `help save` for more options.\n
9. To delete all the packets use
    `reset`\n
10. For karaoke use
    `hello`
    Turn the volume up ;-)\n
"""

        else:
            instructions = """
1. To clear the current filter use
    `clear_filter`\n
2. To display filtered packets
    `display {# of packets}`\n
3. To show protocol statistics use
    `distribution`\n
4. To show packet arrival time statistics use
    `delayviz`\n
5. To show the most active hosts use
    `top_talkers`\n
6. To show the full filtered packet use
    `expand {filtered packet #}`\n
7. To show packet summaries (non filtered) use 
    `show {# of packets}`\n
    Use `show` to show all packets\n
8. To save the packets in a txt file use
    `save`\n
    Use `help save` for more options.\n
9. To delete all the packets use
    `reset`\n
10. For karaoke use
    `hello`
    Turn the volume up ;-)\n
\n """

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
        os.system('ls')
        print()


    def do_protodist(self, arg):
        '''
        `distribution`

        Shows the protocol distribution
        '''
        if not self.all_packets:
            print("\nNo packets to report on. Please read a file first.\n")
            return
        
        # print(self.all_packets)

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
    

    def do_delayviz(self, arg):
        '''
        `packet_distribution`

        Displays a time-series graph of the delay of packets' arrival time between to hosts  

        '''
        if not self.all_packets:
            print("No packets to report on. Please read a file first.")
            return
        
        print("Enter the source and destination IP addresses:")
        src_ip = input("Source IP address: ").strip()
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
            print("\nIncorrect IP addresses. Enter IP addresses that exchange packets.\n")
            return

        print("\n\nThe time difference list: \n\n", diff_times)
        print("\n\n")
        plt.plot(diff_times, color='red+')
        plt.title("Packet Arrival Time Difference in Milliseconds")
        plt.xlabel("Packet #")
        plt.ylabel("Time Difference")
        # plt.colorize("integer color codes", 201, "default", 158, True)
        plt.show()
        print("\n Scroll up above the graph for additional information.\n")
        print("Use `menu` to show the menu\n")


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


    def valid_filetype(self, file_name):
        # validate file type
        return file_name.endswith('.txt')
 

    def valid_path(self, path):
        # validate file path
        return os.path.exists(path)



if __name__ == "__main__":
    sniffsift().cmdloop()

