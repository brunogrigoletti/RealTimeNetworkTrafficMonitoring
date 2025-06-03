from winpcapy import WinPcapUtils, WinPcapDevices
import struct

def mac_addr(bytes_addr):
    return ':'.join('%02x' % b for b in bytes_addr)

def packet_callback(win_pcap, param, header, pkt_data):
    eth_header = pkt_data[:14]
    if len(eth_header) < 14:
        return
    eth = struct.unpack('!6s6sH', eth_header)
    print("\nEthernet Header:")
    print(f"  Dest MAC: {mac_addr(eth[0])}")
    print(f"  Src MAC:  {mac_addr(eth[1])}")
    print(f"  Protocol: {eth[2]:#06x}")

def list_interfaces():
    with WinPcapDevices() as devices:
        device_list = []
        for i, device in enumerate(devices):
            desc = device.description.decode() if isinstance(device.description, bytes) else device.description
            desc = desc if desc else "No description available"
            print(f"{i}: {desc}")
            device_list.append(desc)
        idx = int(input("Type the interface number to start capturing: "))
        return device_list[idx]

def main():
    interface = list_interfaces()
    print(f"Starting capture at '{interface}':")

    try:
        while True:
            WinPcapUtils.capture_on(interface, packet_callback)
    except KeyboardInterrupt:
        print("\nCapture interrupted.")

if __name__ == "__main__":
    main()