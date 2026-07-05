import socket   
import struct

def get_mac_address(bytes_address):

        return ':'.join(
            map(
                '{:02x}'.format,
                bytes_address
            )
        ).upper()

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

def parse_tcp(data):

        source_port, destination_port = struct.unpack(
            "!HH",
            data[:4]
        )

        offset_reserved_flags = struct.unpack(
              "!H",
              data[12:14]
        )[0]

        flag_urg = (offset_reserved_flags & 32) != 0
        flag_ack = (offset_reserved_flags & 16) != 0
        flag_psh = (offset_reserved_flags & 8) != 0
        flag_rst = (offset_reserved_flags & 4) != 0
        flag_syn = (offset_reserved_flags & 2) != 0
        flag_fin = (offset_reserved_flags & 1) != 0

        return (
            source_port, 
            destination_port,
            flag_urg,
            flag_ack,
            flag_psh,
            flag_rst,
            flag_syn,
            flag_fin
        )

def get_protocol_name(protocol):
      
      protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
      }

      return protocols.get(protocol, "Unknown")

def parse_udp(data):

    source_port, destination_port, length, checksum = struct.unpack(
        "!HHHH",
        data[:8]
    )

    return (
        source_port,
        destination_port,
        length
    )

def main():

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

        protocol_name = get_protocol_name(ip_protocol)

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
        print(f"Protocol     : {protocol_name} ({ip_protocol})")
        print(f"Source IP    : {source_ip}")
        print(f"Dest IP      : {destination_ip}")

        print("=" * 50)

        if ip_protocol == 6:

            tcp_start = 14 + header_length

            (
                  source_port,
                  destination_port,
                  urg,
                  ack,
                  psh,
                  rst,
                  syn,
                  fin
            ) = parse_tcp(
                  raw_data[tcp_start:]
            )

            print()
            print("TCP")
            print("-" * 20)
            print(f"Source Port   : {source_port}")
            print(f"Dest Port     : {destination_port}")

            print("Flags")
            print("-" * 20)
            print(f"SYN : {syn}")
            print(f"ACK : {ack}")
            print(f"FIN : {fin}")
            print(f"RST : {rst}")
            print(f"PSH : {psh}")
            print(f"URG : {urg}") 

        elif ip_protocol == 17:
              
              udp_start = 14 + header_length

              source_port, destination_port, length = parse_udp(
                    raw_data[udp_start:]
              )

              print()
              print("UDP")
              print("-" * 20)
              print(f"Source Port  : {source_port}")
              print(f"Dest Port    : {destination_port}")
              print(f"Length       : {length}")
                 
if __name__ == "__main__":
    main()