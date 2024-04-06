import pyshark
import subprocess

def parse(hexdump):
    #subprocess.check_output(['ls', '-l'])  # All that is technically needed...

    #convert from hex dump to pcap through the commad line
    # subprocess.run(['text2pcap', hexdump, 'mycapture3.pcap', '-F', 'pcap'])
    # print('\n\n')

    try:
        cap = pyshark.FileCapture('mycapture3.pcap')

        lst_packet_summary = []
        lst_packet_layers = []
        lst_packet_dict = []

        for pkt in cap:
            try:
                ps, pl, lpd = summary(pkt)
                if ps:
                    lst_packet_summary.append(ps)
                    lst_packet_layers.append(pl)
                    lst_packet_dict.append(lpd)
            except Exception as e:
                print(f"Skipping a problematic packet due to error: {e}")
        # print('lst_packet_summary:', lst_packet_summary)
        # print('lst_packet_dict', lst_packet_dict)
        return lst_packet_summary, lst_packet_layers, lst_packet_dict

    except Exception as e:
        print(f"Failed to parse pcap file due to error: {e}")
        return [], [], []

    # the summary of the third packet in the list of DNS/DHCP packets
    # print(lst_packet_summary[2]) 
    
    # the last full content of the last layer of the third packet in the list of DNS/DHCP packets
    # print(dir(lst_packet_layers[2][-1])) 

    # for item in lst_packet_layers:
    #     print(item)
    

def summary(pkt):
    packet_summary = []
    lst_layer = []
    packet_list_dict = []
    layers = str(pkt.layers)

    # print(layers)

    if (pkt.highest_layer == "DNS" or "DHCP" in pkt.highest_layer or (pkt.highest_layer == "DATA" and pkt.transport_layer == "UDP")):

        # print(pkt)
        packet_dict = {}
        if ("ETH" in layers):
            packet_summary.append( ", ".join(["Ethernet II", "Src: "+pkt.eth.src, "Dst: "+pkt.eth.dst]) )
            lst_layer.append(pkt.eth)
            packet_dict["eth"] = ["Src: "+ pkt.eth.src, "Dst: "+pkt.eth.dst]
        
        
        
        if ("IP" in layers):
            if ("IPV6" in layers):
                packet_summary.append( ", ".join(["Internet Protocol Version (IPV6) "+pkt.ipv6.version, "Src: "+pkt.ipv6.src, "Dst: "+pkt.ipv6.dst]) )
                lst_layer.append(pkt.ipv6)
                packet_dict["ip"] = ["Version: "+pkt.ipv6.version,"Src: "+pkt.ipv6.src, "Dst: "+pkt.ipv6.dst]

            else:
                packet_summary.append( ", ".join(["Internet Protocol Version (IPV4) "+pkt.ip.version, "Src: "+pkt.ip.src, "Dst: "+pkt.ip.dst]) )
                lst_layer.append(pkt.ip)
                packet_dict["ip"] = ["Version: "+pkt.ip.version,"Src: "+pkt.ip.src, "Dst: "+pkt.ip.dst]


        if ("UDP" in layers):
            # print("Yo!\n")
            packet_summary.append( ", ".join(["User Datagram Protocol", "Src Port: "+pkt.udp.srcport, "Dst Port: "+pkt.udp.dstport]) )
            lst_layer.append(pkt.udp)
            # print(packet_summary)
            packet_dict["udp"] = ["Src Port: "+pkt.udp.srcport, "Dst Port: "+pkt.udp.dstport]
            
        if ("DNS" in layers):
            packet_summary.append( "DNS is here!")
            lst_layer.append(pkt.dns)
            # packet_dict["dns"] = ["DNS: "+pkt.dns.qry_name]
        
        if ("DHCP" in layers):
            packet_summary.append( "DHCP is here!")
            lst_layer.append(pkt.dhcpv6)
            # packet_dict["dhcp"] = ["DHCP: "+pkt.dhcpv6.options]

        if ("DATA" in layers):
            packet_summary.append("Data (" + pkt.data.data_len + " bytes)")
            lst_layer.append("Data: {0}\n[Length: {1}]".format(pkt.data.data, pkt.data.data_len))
            packet_dict["data"] = ["Data: "+pkt.data.data, "Length: "+pkt.data.data_len]
        
        packet_list_dict.append(packet_dict)

    if len(packet_summary):
        return packet_summary, lst_layer, packet_list_dict
    return None, None, None 

if __name__ == "__main__":
    # parse()
    parse("test3.txt") 