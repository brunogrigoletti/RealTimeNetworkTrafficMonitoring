import datetime
import struct
import threading
from winpcapy import WinPcapUtils, WinPcapDevices

def mac_addr(bytes_addr):
    # Converte endereço MAC em bytes para String legível
    return ':'.join('%02x' % b for b in bytes_addr)

def packet_callback(win_pcap, param, header, pkt_data):
    # Obtém o timestamp do header
    ts_sec = header.contents.ts.tv_sec
    ts_usec = header.contents.ts.tv_usec
    timestamp = datetime.datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000)

    # Extrai e processa o cabeçalho Ethernet do pacote capturado
    eth_header = pkt_data[:14]
    if len(eth_header) < 14:
        return
    
    # Desempacota o cabeçalho Ethernet
    # '!6s': 6 bytes para o endereço MAC de destino
    # '6s': 6 bytes para o endereço MAC de origem
    # 'H': 2 bytes para o campo "EtherType" (protocolo)
    # '!': ordem de bytes network (big-endian)
    eth = struct.unpack('!6s6sH', eth_header)

    # Dicionário EtherType para nome do protocolo
    ethertype_names = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
    }
    proto_hex = eth[2]
    proto_name = ethertype_names.get(proto_hex, "Unknown")

    print("=" * 50)

    print("\nEthernet Header:")
    print(f"  Timestamp: {timestamp.strftime('%d/%m/%Y %I:%M:%S %p')}")
    print(f"  Source MAC: {mac_addr(eth[1])}")
    print(f"  Destination MAC: {mac_addr(eth[0])}")
    print(f"  Protocol: {eth[2]:#06x} - {proto_name}")
    print(f"  Length: {header.contents.len} bytes")

    # Extrai e processa o cabeçalho IPv4 do pacote capturado
    ip4_header = pkt_data[14:34]
    if len(ip4_header) < 20:
        return
    
    # Desempacota o cabeçalho IPv4
    # '!': ordem de bytes network (big-endian)
    # 'B': 1 byte para Versão + IHL (Internet Header Length)
    # 'B': 1 byte para Type of Service (ToS)
    # 'H': 2 bytes para Total Length do pacote
    # 'H': 2 bytes para Identification
    # 'H': 2 bytes para Flags + Fragment Offset
    # 'B': 1 byte para Time To Live (TTL)
    # 'B': 1 byte para Protocol (identificador)
    # 'H': 2 bytes para Header Checksum
    # '4s': 4 bytes para o IP de origem
    # '4s': 4 bytes para o IP de destino
    ipv4 = struct.unpack('!BBHHHBBH4s4s', ip4_header)
 
    print("\nIPv4 Header:")
    print(f"  Timestamp: {timestamp.strftime('%d/%m/%Y %I:%M:%S %p')}")
    print(f"  Source IP: {'.'.join(map(str, ipv4[8]))}")
    print(f"  Destination IP: {'.'.join(map(str, ipv4[9]))}")
    print(f"  Protocol ID: {ipv4[6]}")
    print(f"  Length: {header.contents.len} bytes")

    # Extrai e processa o cabeçalho IPv6 do pacote capturado
    ip6_header = pkt_data[14:54]
    if len(ip6_header) < 40:
        return
    
    # Desempacota o cabeçalho IPv6
    # '!': ordem de bytes network (big-endian)
    # 'I': 4 bytes para Versão, Traffic Class e Flow Label
    # 'H': 2 bytes para Payload Length
    # 'B': 1 byte para Next Header (identificador)
    # 'B': 1 byte para Hop Limit (TTL do IPv6)
    # '16s': 16 bytes para o IP de origem
    # '16s': 16 bytes para o IP de destino
    ipv6 = struct.unpack('!IHBB16s16s', ip6_header)

    src_ip = ':'.join(f"{ipv6[4][i]<<8 | ipv6[4][i+1]:x}" for i in range(0,16,2))
    dst_ip = ':'.join(f"{ipv6[5][i]<<8 | ipv6[5][i+1]:x}" for i in range(0,16,2))    

    print("\nIPv6 Header:")
    print(f"  Timestamp: {timestamp.strftime('%d/%m/%Y %I:%M:%S %p')}")
    print(f"  Source IP: {src_ip}")
    print(f"  Destination IP: {dst_ip}")
    print(f"  Protocol ID: {ipv6[2]}")
    print(f"  Length: {header.contents.len} bytes")

    # Extrai e processa o cabeçalho de transporte do pacote capturado
    transport_header = None
    # TCP
    if ipv4[6] == 6:
        transport_header = pkt_data[34:54]

        # Desempacota o cabeçalho de transporte TCP
        # '!': ordem de bytes network (big-endian)
        # 'H': 2 bytes para Porta de Origem
        # 'H': 2 bytes para Porta de Destino
        # 'L': 4 bytes para Número de Sequência
        # 'L': 4 bytes para Número de Acknowledgment
        # 'B': 1 byte para Data Offset + Reserved + Flags
        # 'B': 1 byte para Janela (Window Size)
        # 'H': 2 bytes para Checksum
        # 'H': 2 bytes para Urgent Pointer
        # 'H': 2 bytes para Opções (se houver)
        tcp = struct.unpack('!HHLLBBHHH', transport_header)
    # UDP
    elif ipv6[2] == 17:
        transport_header = pkt_data[34:42]

        # Desempacota o cabeçalho de transporte UDP
        # '!': ordem de bytes network (big-endian)
        # 'H': 2 bytes para Porta de Origem
        # 'H': 2 bytes para Porta de Destino
        # 'H': 2 bytes para Comprimento
        # 'H': 2 bytes para Checksum
        udp = struct.unpack('!HHHH', transport_header) 

    print("\nTransport Header:")
    print(f"  Timestamp: {timestamp.strftime('%d/%m/%Y %I:%M:%S %p')}")
    print(f"  Protocol: {'TCP' if ipv4[6] == 6 else 'UDP' if ipv6[2] == 17 else 'Unknown'}")
    print(f"  Source IP: {'.'.join(map(str, ipv4[8])) if transport_header and ipv4[6] == 6 else src_ip if transport_header and ipv6[2] == 17 else 'N/A'}")
    print(f"  Source Port: {tcp[0] if transport_header and ipv4[6] == 6 else udp[0] if transport_header and ipv6[2] == 17 else 'N/A'}")
    print(f"  Destination IP: {'.'.join(map(str, ipv4[9])) if transport_header and ipv4[6] == 6 else dst_ip if transport_header and ipv6[2] == 17 else 'N/A'}")
    print(f"  Destination Port: {tcp[1] if transport_header and ipv4[6] == 6 else udp[1] if transport_header and ipv6[2] == 17 else 'N/A'}")
    print(f"  Length: {header.contents.len} bytes")

    print("=" * 50)

def list_interfaces():
    # Lista todas as interfaces disponíveis para captura
    with WinPcapDevices() as devices:
        device_list = []
        for i, device in enumerate(devices):
            desc = device.description.decode() if isinstance(device.description, bytes) else device.description
            desc = desc if desc else "No description available"
            print(f"{i}: {desc}")
            device_list.append(desc)

        # Escolha da interface pelo índice
        idx = int(input("Type the interface number to start capturing: "))
        return device_list[idx]

stop_event = threading.Event()

def capture_packets(interface):
    try:
        while not stop_event.is_set():
            WinPcapUtils.capture_on(interface, packet_callback)
    except Exception as e:
        print(f"Capture error: {e}")

def main():
    interface = list_interfaces()
    print(f"Selected interface: '{interface}'")
    capture_thread = None

    while True:
        cmd = input("Type 'cat' to start capturing, 'stop' to stop, or 'exit' to exit: ").strip().lower()
        if cmd == "cat":
            if capture_thread and capture_thread.is_alive():
                print("Capture is already running!")
            else:
                stop_event.clear()
                capture_thread = threading.Thread(target=capture_packets, args=(interface,), daemon=True)
                capture_thread.start()
                print("Capture started!")
        elif cmd == "stop":
            if capture_thread and capture_thread.is_alive():
                stop_event.set()
                capture_thread.join()
                print("Capture stopped!")
            else:
                print("No capture is running!")
        elif cmd == "exit":
            if capture_thread and capture_thread.is_alive():
                stop_event.set()
                capture_thread.join()
            print("Exiting...")
            break
        else:
            print("Unknown command!")

if __name__ == "__main__":
    main()