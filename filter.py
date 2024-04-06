import pyshark


#Change the file as needed
pcap_file = ''

# Initialize PyShark capture
original_cap = pyshark.FileCapture(pcap_file, keep_packets=True)
filtered_packets = []
current_filters = {'src_ip': None, 'dst_ip': None, 'protocol': None}

def apply_filters(packet):
    try:
        if current_filters['src_ip'] and packet.ip.src != current_filters['src_ip']:
            return False
        if current_filters['dst_ip'] and packet.ip.dst != current_filters['dst_ip']:
            return False
        if current_filters['protocol'] and current_filters['protocol'].upper() not in packet:
            return False
    except AttributeError:  # If any attribute is missing, the packet does not match
        return False
    return True

def update_filtered_packets():
    global filtered_packets
    filtered_packets = [packet for packet in original_cap if apply_filters(packet)]
    original_cap.reset()  # Reset iterator for the original capture

def set_filter(src_ip=None, dst_ip=None, protocol=None):
    current_filters['src_ip'] = src_ip
    current_filters['dst_ip'] = dst_ip
    current_filters['protocol'] = protocol
    update_filtered_packets()

def reset_filters():
    set_filter()  # Clears current filter settings

def print_packet_details(packet):
    print(f"Packet Number: {packet.number}")
    try:
        print(f"Protocol: {packet.transport_layer}, Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}", end='')
        if 'TCP' in packet or 'UDP' in packet:
            print(f", Src Port: {packet[packet.transport_layer].srcport}, Dst Port: {packet[packet.transport_layer].dstport}", end='')
        print()
    except AttributeError:  # For non-IP or non-TCP/UDP packets
        print(" -- Non-IP or non-TCP/UDP packet --")
    print("-" * 50)  # Separator for readability

def view_packets(packets):
    for packet in packets:
        print_packet_details(packet)

def main_menu():
    while True:
        print("\nMain Menu:")
        print("1. View Original Packets")
        print("2. View Filtered Packets")
        print("3. Set Filter")
        print("4. Reset Filter")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            view_packets(original_cap)
            original_cap.reset()  # Reset iterator for the original capture
        elif choice == '2':
            view_packets(filtered_packets)
        elif choice == '3':
            src_ip = input("Enter source IP to filter by (leave blank for none): ")
            dst_ip = input("Enter destination IP to filter by (leave blank for none): ")
            protocol = input("Enter protocol to filter by (TCP, UDP, etc., leave blank for none): ")
            set_filter(src_ip=src_ip or None, dst_ip=dst_ip or None, protocol=protocol.upper() if protocol else None)
            print("Filter set. Use 'View Filtered Packets' to see results.")
        elif choice == '4':
            reset_filters()
            print("Filters reset.")
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main_menu()
