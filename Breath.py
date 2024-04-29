import cmd
import subprocess
import pyshark
import plotext as plt
import os

class sniffsift(cmd.Cmd):
    
    def __init__(self) :
        super().__init__()
        self.file = None 
        self.all_packets = [] # list of objects, each object contains the whole packet, and a summary (src/ dst IP and protocol)
        self.original_packets = []
        self.last_filtered_packets = []
        self.current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None}
        self.filtered_packets = []

    # Existing code...

    def read(self, hexdump_file):
        '''
        Converts hexdump text file to PCAP and extracts UDP data.
        '''
        try:
            subprocess.run(['text2pcap', hexdump_file, 'mycapture.pcap', '-F', 'pcap'])
            self.file = hexdump_file
            print("Hexdump converted to PCAP successfully.")
            self.extract_udp_data_from_pcap('mycapture.pcap')
        except Exception as e:
            print(f"Error converting hexdump to PCAP: {e}")

    def extract_udp_data_from_pcap(self, pcap_file):
        '''
        Extracts UDP data from PCAP file.
        '''
        try:
            cap = pyshark.FileCapture(pcap_file)
            udp_data = []

            for pkt in cap:
                if 'UDP' in pkt:
                    udp_info = {
                        "Time since previous frame": float(pkt.sniff_timestamp),
                        "Source Port": int(pkt.udp.srcport),
                        "Destination Port": int(pkt.udp.dstport)
                    }
                    udp_data.append(udp_info)

            self.plot_udp_data_distribution(udp_data)
        except Exception as e:
            print(f"Error extracting UDP data from PCAP: {e}")

    def plot_udp_data_distribution(self, udp_data):
        '''
        Plots the distribution of UDP data.
        '''
        # Ask for user input
        target_port = int(input("Enter the source port: "))
        target_destination = int(input("Enter the destination port: "))

        filtered_data_source = [(data["Time since previous frame"] * 1000, data["Destination Port"]) for data in udp_data if data["Source Port"] == target_port and data["Destination Port"] == target_destination]
        filtered_data_destination = [(data["Time since previous frame"] * 1000, data["Source Port"]) for data in udp_data if data["Source Port"] == target_destination and data["Destination Port"] == target_port]
        
        if filtered_data_source:
            x_values_source = [int(point[0]) for point in filtered_data_source]
            y_values_source = [point[1] for point in filtered_data_source]
            plt.scatter(x_values_source, y_values_source, marker="x", color="red", label=f"Port {target_port} to {target_destination}")

        if filtered_data_destination:
            x_values_destination = [int(point[0]) for point in filtered_data_destination]
            y_values_destination = [point[1] for point in filtered_data_destination]
            plt.scatter(x_values_destination, y_values_destination, marker="o", color="blue", label=f"Port {target_destination} to {target_port}")

        if filtered_data_source or filtered_data_destination:
            plt.title("UDP Data")
            plt.xlabel("Time since previous frame (ms)")
            plt.ylabel("Destination Port")
            plt.grid(True)
            plt.show()
        else:
            print(f"No data found for port {target_port} to destination {target_destination}")

    # Existing code...

if __name__ == "__main__":
    sniffsift().cmdloop()
