import cmd
from read_packets import parse
import os

class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()
        self.file = None 
        self.all_packets = []
        self.last_filtered_packets = []

    def default(self, line):
        print(f"Unknown command: {line} \nPlease use 'help' to see a list of commands")

    prompt = "+_+ "
    intro = '\nWelcome to sniffsift, an offline network traffic analyzer.\nThe input of the analyzer is a hexdump text file. Type "help" to see all the available commands. For information on how to use a command, type "help + {command_name}"\n'

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
        try:
            summary, layers, _ = parse(self.file)
            for item in summary:
                print(f"Packet {count}")
                src, dst, protocol = "Unknown", "Unknown", "Unknown"
                for subitem in item:
                    print(subitem)
                    # Example extraction logic based on your summary structure
                    if "Src:" in subitem:
                        src = subitem.split("Src: ")[1].split(",")[0]
                    if "Dst:" in subitem:
                        dst = subitem.split("Dst: ")[1]
                    if any(proto in subitem for proto in ["Ethernet", "Internet Protocol", "User Datagram"]):
                        protocol = subitem.split(",")[0]  # Simplistic approach

                self.all_packets.append({"src": src, "dst": dst, "protocol": protocol})
                count += 1
                print()

        except Exception as e:
            print(f"Failed to read or parse the file: {e}")
        print(f"Read and stored {len(self.all_packets)} packets.")
    
    def do_filter(self, arg):
        '''
        `filter {filter_string}`

        Filter packets based on the filter string. The filter string should be in the format:
        "src_ip={src_ip},dst_ip={dst_ip},src_port={src_port},dst_port={dst_port},size={size}"
        You can include any combination of these filters.
        '''
        # TODO: filter multiple in the same read
        # TODO: send the actual summary instead of the list of dicts 
        # Parse the filter string into a dictionary
        filters = {}
        try:
            for item in arg.split(","):
                key, value = item.split("=")
                key = key.replace('"', '')
                value = value.replace('"', '')
                filters[key] = value
        except:
            print("Invalid filter format. Please use the format src_ip={src_ip},dst_ip={dst_ip},src_port={src_port},dst_port={dst_port},size={size} You can include any combination of these filters.")
            return

        print("my filters", filters)

        filters_count = len(filters)
        print("filters_count", filters_count)
        # Read and parse the packets
        summary, layers, list_packet_dict = parse(self.file)
        print("list_packet_dict", list_packet_dict)
        # Filter the packets
        filtered_packets = []
        for packet in range(len(list_packet_dict)):
            # handle filter by port
            matched = 0 
            if 'src_port' in filters and list_packet_dict[packet][0]['eth'][0] == 'Src: '+filters['src_port']:
                matched +=1
            if 'dst_port' in filters and list_packet_dict[packet][0]['eth'][1] == 'Dst: '+filters['dst_port']:
                matched +=1
            # handle filter by IP
            if 'src_ip' in filters and list_packet_dict[packet][0]['ip'][1] == 'Src: '+filters['src_ip']:
                matched +=1
            if 'dst_ip' in filters and list_packet_dict[packet][0]['ip'][2] == 'Dst: '+filters['dst_ip']:
                matched +=1
            # handle filter by size (data length)
            # check if the packet has data first
            if 'size' in filters and 'data' in list_packet_dict[packet][0] and list_packet_dict[packet][0]['data'][1] == 'Length: '+filters['size']:
                matched +=1
            if matched == filters_count:
                filtered_packets.append(list_packet_dict[packet])
            # test filter is below
            #  filter "src_port=00:14:0b:33:33:27,dst_port=d0:7a:b5:96:cd:0a,src_ip=192.168.1.101,dst_ip=67.252.131.62,size=10"

        # Print the filtered packets
        print("the length of the filtered packets is" , len(filtered_packets))
        print("Filtered packets:")
        # print(filtered_packets)
        for packet in filtered_packets:
            print(packet)
            print()
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

    def do_graph(self, flag):
        '''
        `graph {flag}`

        Visualize packet flows. Flag 0 for all packets, 1 for filtered packets.
        '''
        flag = flag.strip()
        if flag not in ['0', '1']:
            print("Invalid flag. Use 0 for all packets or 1 for filtered packets.")
            return

        packets_to_graph = self.last_filtered_packets if flag == '1' else self.all_packets

        if not packets_to_graph:
            print("No packets to display. Please ensure packets are loaded or filtered correctly.")
            return

        print("Packet Flows:")
        print("----------------------------------------------------------------")

        for idx, packet in enumerate(packets_to_graph, start=1):
            src = packet.get("src", "Unknown")
            dst = packet.get("dst", "Unknown")
            protocol = packet.get("protocol", "Unknown")

            # Creating a multi-line format for each packet
            print(f"Packet #{idx}:")
            print(f"  Source:      {src}")
            print(f"               |")
            print(f"               |  [{protocol}]")
            print(f"               V")
            print(f"  Destination: {dst}\n")
            print("----------------------------------------------------------------")
    
    def do_distribution(self, arg):
        '''
        'distribution`

        Shows the protocol distribution
        '''
        protocol_counts = {}
        for packet in self.all_packets:
            protocol = packet.get("protocol", "Unknown")
            if protocol not in protocol_counts:
                protocol_counts[protocol] = 0
            protocol_counts[protocol] += 1

        total_packets = sum(protocol_counts.values())
        print("Protocol Distribution:")
        for protocol, count in protocol_counts.items():
            percentage = (count / total_packets) * 100
            print(f"{protocol}: {percentage:.2f}% ({count} packets)")
        

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

