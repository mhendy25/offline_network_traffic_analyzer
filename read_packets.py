import pyshark
import subprocess

def parse(hexdump, flag=True):
    # subprocess.check_output(['ls', '-l'])  # All that is technically needed...

    # convert from hex dump to pcap through the commad line
    if flag:
        subprocess.run(['text2pcap', hexdump, 'mycapture.pcap', '-F', 'pcap'])
        print("\n\n")

    cap = pyshark.FileCapture('mycapture.pcap')

    # print(cap[128].dns)

    lst_packet_summary = []
    lst_packet_layers = []
    lst_packet_dict = []
    for pkt in cap:
        ps, pl, lpd = summary(pkt)
        if ps:
            lst_packet_summary.append(ps)
            lst_packet_layers.append(pl)
            lst_packet_dict.append(lpd)

    # print('lst_packet_summary:', lst_packet_summary)
    # print('lst_packet_dict', lst_packet_dict)

    return lst_packet_summary, lst_packet_layers, lst_packet_dict

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
            if (pkt.dns.flags_response == "True"):
                packet_summary.append( "Domain Name System (response)")
            else:
                packet_summary.append( "Domain Name System (query)")

            lst_layer.append(pkt.dns)
            # packet_dict["dns"] = ["DNS: "+pkt.dns.qry_name]
        
        if ("DHCP" in layers):
            # packet_dict["dhcp"] = ["DHCP: "+pkt.dhcpv6.options]
            if ("DHCPV6" in layers):
                packet_summary.append("DHCPV6")
                lst_layer.append(pkt.dhcpv6)
            else:
                packet_summary.append("DHCP")
                lst_layer.append(pkt.dhcp)

        if ("DATA" in layers):
            packet_summary.append("Data (" + pkt.data.len + " bytes)")
            lst_layer.append("Data: {0}\n[Length: {1}]".format(pkt.data.data, pkt.data.len))
            packet_dict["data"] = ["Data: "+pkt.data.data, "Length: "+pkt.data.len]
        
        packet_list_dict.append(packet_dict)

    if len(packet_summary):
        return packet_summary, lst_layer, packet_list_dict
    return None, None, None 

if __name__ == "__main__":
    # parse()
    parse("test.txt") 