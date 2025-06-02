from scapy.all import sniff, Ether

def packet_callback(packet):
    if Ether in packet:
        dst_mac = packet[Ether].dst
        src_mac = packet[Ether].src
        # print(f"MAC Destination: {dst_mac}")
        # print(f"MAC Source:  {src_mac}\n")

        print("="*40)
        packet.show()
        print("="*40)

def main():
    iface = "Wi-Fi"
    print(f"Capturing packets from {iface}:")
    sniff(prn=packet_callback, iface=iface, store=0)

if __name__ == "__main__":
    main()