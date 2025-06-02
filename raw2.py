import socket
import struct

def mac_addr(bytes_addr):
    return ':'.join('%02x' % b for b in bytes_addr)

def main():
    iface = 'eth0'
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((iface, 0))

    while True:
        raw_data, addr = s.recvfrom(65535)
        print("="*40)
        # Ethernet header
        eth_header = raw_data[:14]
        eth = struct.unpack('!6s6sH', eth_header)
        print(f"Ethernet Header:")
        print(f"  Dest MAC: {mac_addr(eth[0])}")
        print(f"  Src MAC:  {mac_addr(eth[1])}")
        print(f"  Protocol: {eth[2]:#06x}")

        # IP header (if present)
        if eth[2] == 0x0800:  # IPv4
            ip_header = raw_data[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = (version_ihl & 0xF) * 4
            print(f"IP Header:")
            print(f"  Version: {version}")
            print(f"  Header Length: {ihl}")
            print(f"  TTL: {iph[5]}")
            print(f"  Protocol: {iph[6]}")
            print(f"  Src IP: {socket.inet_ntoa(iph[8])}")
            print(f"  Dest IP: {socket.inet_ntoa(iph[9])}")

            # TCP or UDP header
            if iph[6] == 6:  # TCP
                tcp_header = raw_data[14+ihl:14+ihl+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                print(f"TCP Header:")
                print(f"  Src Port: {tcph[0]}")
                print(f"  Dest Port: {tcph[1]}")
            elif iph[6] == 17:  # UDP
                udp_header = raw_data[14+ihl:14+ihl+8]
                udph = struct.unpack('!HHHH', udp_header)
                print(f"UDP Header:")
                print(f"  Src Port: {udph[0]}")
                print(f"  Dest Port: {udph[1]}")
        print("="*40)

if __name__ == "__main__":
    main()