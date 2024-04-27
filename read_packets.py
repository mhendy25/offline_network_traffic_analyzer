import pyshark
import subprocess


class packet():
    def __init__(self, s, l, fp):
        self.summary = s
        self.layers = l
        self.full_packet = fp

    def __str__(self):
        return "\n".join(self.summary)
        
def parse(hexdump):

    try:
        #convert from hex dump to pcap through the commad line
        subprocess.run(['text2pcap', hexdump, 'mycapture.pcap', '-F', 'pcap'])
        print('\n\n')

        cap = pyshark.FileCapture('mycapture.pcap')

        lst_packet = []
        # lst_packet_dict = []

        for pkt in cap:
            p = summary(pkt)
            if p:
                lst_packet.append(p)
                # lst_packet_dict.append(lpd)
        subprocess.run(['rm','mycapture.pcap'])
        return lst_packet

    # except Exception as e:
        # print(f"Failed to parse pcap file due to error: {e}")
    except FileNotFoundError:
        return []
    

def summary(pkt):
    packet_summary = []
    lst_layer = []
    # packet_list_dict = []
    layers = str(pkt.layers)

    # print(layers)

    if (pkt.highest_layer == "DNS" or "DHCP" in pkt.highest_layer or (pkt.highest_layer == "DATA" and pkt.transport_layer == "UDP")):

        # print(pkt)
        # packet_dict = {}
        if ("ETH" in layers):
            packet_summary.append( ", ".join(["Ethernet II", "Src: "+pkt.eth.src, "Dst: "+pkt.eth.dst]) )
            lst_layer.append(pkt.eth)
            # packet_dict["eth"] = ["Src: "+ pkt.eth.src, "Dst: "+pkt.eth.dst]
        
        if ("IP" in layers):
            if ("IPV6" in layers):
                packet_summary.append( ", ".join(["Internet Protocol Version "+pkt.ipv6.version, "Src: "+pkt.ipv6.src, "Dst: "+pkt.ipv6.dst]) )
                lst_layer.append(pkt.ipv6)
                # packet_dict["ip"] = ["Version: "+pkt.ipv6.version,"Src: "+pkt.ipv6.src, "Dst: "+pkt.ipv6.dst]

            else:
                packet_summary.append( ", ".join(["Internet Protocol Version "+pkt.ip.version, "Src: "+pkt.ip.src, "Dst: "+pkt.ip.dst]) )
                lst_layer.append(pkt.ip)
                # packet_dict["ip"] = ["Version: "+pkt.ip.version,"Src: "+pkt.ip.src, "Dst: "+pkt.ip.dst]

        if ("UDP" in layers):
            # print("Yo!\n")
            packet_summary.append( ", ".join(["User Datagram Protocol", "Src Port: "+pkt.udp.srcport, "Dst Port: "+pkt.udp.dstport]) )
            lst_layer.append(pkt.udp)
            # print(packet_summary)
            # packet_dict["udp"] = ["Src Port: "+pkt.udp.srcport, "Dst Port: "+pkt.udp.dstport]
            
        if ("DNS" in layers):
            if (pkt.dns.flags_response == "True"):
                packet_summary.append( "Domain Name System (response)")
            else:
                packet_summary.append("Domain Name System (query)")

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
            # packet_dict["data"] = ["Data: "+pkt.data.data, "Length: "+pkt.data.len]
        
        # packet_list_dict.append(packet_dict)

    if len(packet_summary):
        p = packet(packet_summary, lst_layer, pkt)
        return p
    return None

if __name__ == "__main__":
    # parse()
    parse("test.txt") 