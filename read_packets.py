import pyshark
import subprocess

def parse(hexdump):
    #subprocess.check_output(['ls', '-l'])  # All that is technically needed...

    #convert from hex dump to pcap through the commad line
    subprocess.run(['text2pcap', hexdump, 'mycapture3.pcap', '-F', 'pcap'])
    print('\n\n')

    cap = pyshark.FileCapture('mycapture3.pcap')

    lst_packet_summary = []
    lst_packet_layers = []

    for pkt in cap:
        ps, pl = summary(pkt)
        if ps:
            lst_packet_summary += [ps]
            lst_packet_layers += [pl]
            
    return lst_packet_summary, lst_packet_layers

    # the summary of the third packet in the list of DNS/DHCP packets
    # print(lst_packet_summary[2]) 
    
    # the last full content of the last layer of the third packet in the list of DNS/DHCP packets
    # print(dir(lst_packet_layers[2][-1])) 

    # for item in lst_packet_layers:
    #     print(item)
    

def summary(pkt):
    packet_summary = []
    lst_layer = []

    layers = str(pkt.layers)

    # print(layers)

    if (pkt.highest_layer == "DNS" or "DHCP" in pkt.highest_layer or (pkt.highest_layer == "DATA" and pkt.transport_layer == "UDP")):

        # print(pkt)

        if ("ETH" in layers):
            packet_summary.append( ", ".join(["Ethernet II", "Src: "+pkt.eth.src, "Dst: "+pkt.eth.dst]) )
            lst_layer.append(pkt.eth)
        
        
        
        if ("IP" in layers):
            if ("IPV6" in layers):
                packet_summary.append( ", ".join(["Internet Protocol Version "+pkt.ipv6.version, "Src: "+pkt.ipv6.src, "Dst: "+pkt.ipv6.dst]) )
                lst_layer.append(pkt.ipv6)
            else:
                packet_summary.append( ", ".join(["Internet Protocol Version "+pkt.ip.version, "Src: "+pkt.ip.src, "Dst: "+pkt.ip.dst]) )
                lst_layer.append(pkt.ip)

        if ("UDP" in layers):
            # print("Yo!\n")
            packet_summary.append( ", ".join(["User Datagram Protocol", "Src Port: "+pkt.udp.srcport, "Dst Port: "+pkt.udp.dstport]) )
            lst_layer.append(pkt.udp)
            # print(packet_summary)
            
        if ("DNS" in layers):
            packet_summary.append( "DNS is here!")
            lst_layer.append(pkt.dns)
        
        if ("DHCP" in layers):
            packet_summary.append( "DHCP is here!")
            lst_layer.append(pkt.dhcpv6)

        if ("DATA" in layers):
            packet_summary.append("Data (" + pkt.data.len + " bytes)")
            lst_layer.append("Data: {0}\n[Length: {1}]".format(pkt.data.data, pkt.data.len))

    if len(packet_summary):
        return packet_summary, lst_layer
    return None, None

if __name__ == "__main__":
    # parse()
    parse("test3.txt") 
