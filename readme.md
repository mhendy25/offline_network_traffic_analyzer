Welcome to Sniffsift!

# About the project:

You **must** read the project description fully. [Here it is](https://docs.google.com/document/d/1M-ddBvBMP35zRBvscQOrg7LrPI9WOsx9ILS6wI63I4g/edit#heading=h.ercuy2bce6ve). **Please read the description linked above.** Otherwise you will not understand what comes below. 

In the file cli_tool.py is a command line tool that can read and parse packets. You can test it with the text.txt hexdump file. This hexdump has over 700 packets but we only care about 30 of them as per the requirements of the project. **Read the project description above to familiasrize yourself with the requirements.** We go from 700+ to 30 packets because the project requires that we focus on **DNS and DHCP packets** only. 


# Implementation

The workflow is simple:
hexdump plaintext file --> pcap file --> list objects

The transition hexdump plaintext file --> pcap file takes place in read_packets.py. 

read_packets.py returns two lists:
- packet_summary: lst of lst of str (a summary of the layers of a packet)
- lst_layer: lst of lst of layer objets (the full string content of each layer)

The cli_tool.py file is the command line interface. It displays the packets read in read_packets.py via the "read" command. Check the help mannual by running `help command_name` once you have started the command line tool.


# Usage

To use the tool call:
`python cli_tool.py` or `python3 cli_tool.py`

Call `help` to see what commands are available. 
Call `help read` to see how to read a hexdump.txt file.



# Packages

Use pyshark Version: 0.4.3

Set up brew
- get rid of old wireshark. Delete app and run `brew uninstall --force wireshark` to be safe
- Install wireshark by running `brew install wireshark` and `brew install --cask wireshark`
- Check that it worked `brew info --cask wireshark`
- Add an alias to your path directory `alias wireshark='/Applications/Wireshark.app/Contents/MacOS/Wireshark'`
- Install Plotext by running  `pip install plotext`
- To run the program use the following command `./cli_tool.py [.txt file]`. This will read the hexdump and print out the contents.
- To find out more about the tool write `help` or `help + command_name` to learn more about a function
- Run `filter` and then choose your desired filters to filter through different settings like IP addresses, port numbers, packet size, etc
- Run `distribution` to see the protocol break down of the packets including DNS, DHCP, and UDP
