import cmd
from read_packets import parse
import os

class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()
        self.file = None 

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
        summary, layers,_ = parse(self.file)
        for item in summary:
            print("Packet", count)
            for subitem in item:
                print(subitem)
            count+=1
            print()
    

    def do_filter(self, arg):
        '''
        `filter {filter_string}`

        Filter packets based on the filter string. The filter string should be in the format:
        "src_ip={src_ip}, dst_ip={dst_ip}, src_port={src_port}, dst_port={dst_port}, size={size}"
        You can include any combination of these filters.
        '''
        # TODO: filter multiple in the same read
        # TODO: send the actual summary instead of the list of dicts 
        # Parse the filter string into a dictionary

        # pattern = r"(src_ip={[^}]*})?,?\s*(dst_ip={[^}]*})?,?\s*(src_port={[^}]*})?,?\s*(dst_port={[^}]*})?,?\s*(size={[^}]*})?"

        
        filters = {}
        for item in arg.split(","):
            key, value = item.split("=")
            key = key.replace('"', '')
            value = value.replace('"', '')
            filters[key] = value

        # Read and parse the packets

        if (self.file):
            summary, layers, list_packet_dict = parse(self.file, False)
            
        else:
            print("\nOne must first read a packet to filter it!\n")
            return

        print("\nActive filters:\n", filters)

        filters_count = len(filters)
        print("\nNumber of filters: {0}\n".format(filters_count))

        # print("list_packet_dict", list_packet_dict)
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
        print("Number of filtered packets: {0}\n".format(len(filtered_packets)) )



        print("Filtered packets:\n")
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
    

    def validate_file(self, file_name):
        '''
        validate file name and path.
        '''
        # error messages
        INVALID_FILETYPE_MSG = "Error: Invalid file format. %s must be a .txt file."
        INVALID_PATH_MSG = "Error: Invalid file path/name. Path %s does not exist."

        if not self.valid_path(file_name):
            print(INVALID_PATH_MSG%(file_name))
            quit()
        elif not self.valid_filetype(file_name):
            print(INVALID_FILETYPE_MSG%(file_name))
            quit()
        return


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

