import socket   
import struct

def main():
    if protocol == 6:

        tcp_start = 14 + header_length

        source_port, destination_port = parse_tcp(
            raw_data[tcp_start:]
        )

        print("TCP")
        print("-" * 20)
        print(f"Source Port   : {source_port}")
        print(f"Dest Port     : {destination_port}")

    def parse_tcp(data):

        source_port, destination_port = struct.unpack(
            "!HH",
            data[:4]
        )

        return source_port, destination_port

    def ipv4_packet(data):

        version_header_length = data[0]

        version = version_header_length >> 4

        header_length = (version_header_length & 15) * 4

        ttl = data[8]

        protocol = data[9]

        source = socket.inet_ntoa(data[12:16])

        destination = socket.inet_ntoa(data[16:20])

        return (
            version,
            header_length,
            ttl,
            protocol,
            source,
            destination
        )

    def ethernet_frame(data):

        destination_mac, source_mac, protocol = struct.unpack(
            "!6s6sH",
            data[:14]
        )

        return (
            get_mac_address(destination_mac),
            get_mac_address(source_mac),
            socket.htons(protocol),
        )
    
    def get_mac_address(bytes_address):

        return ':'.join(
            map(
                '{:02x}'.format,
                bytes_address
            )
        ).upper()

    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(3)
    )

    print("=" * 50)
    print("CyberScope v0.1")
    print("=" * 50)
    print("Listening for packets ... \n")

    packet_count = 0

    while True:

        raw_data, address = sock.recvfrom(65535)
        destination_mac, source_mac, protocol = ethernet_frame(raw_data)
        (
            version,
            header_length,
            ttl,
            ip_protocol,
            source_ip,
            destination_ip
        ) = ipv4_packet(raw_data[14:])

        packet_count += 1

        print("=" * 50)

        print(f"Packet #{packet_count}")
        
        print()
        
        print("Ethernet")
        print("-" * 20)
        print(f"Source MAC: {source_mac}")
        print(f"Dest MAC  : {destination_mac}")

        print()

        print("IPv4")
        print("-" * 20)
        print(f"Version      : {version}")
        print(f"Header Len   : {header_length}")
        print(f"TTL          : {ttl}")
        print(f"Protocol     : {ip_protocol}")
        print(f"Source IP    : {source_ip}")
        print(f"Dest IP      : {destination_ip}")

        print("=" * 50)
        
if __name__ == "__main__":
    main()