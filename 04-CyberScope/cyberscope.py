import socket   
import struct
import datetime

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

        offset = (offset_reserved_flags >> 12) * 4

        flag_urg = (offset_reserved_flags & 32) != 0
        flag_ack = (offset_reserved_flags & 16) != 0
        flag_psh = (offset_reserved_flags & 8) != 0
        flag_rst = (offset_reserved_flags & 4) != 0
        flag_syn = (offset_reserved_flags & 2) != 0
        flag_fin = (offset_reserved_flags & 1) != 0

        return (
            source_port, 
            destination_port,
            offset,
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

def parse_icmp(data):
     
     icmp_type, code, checksum = struct.unpack(
          "!BBH",
          data[:4]
     )

     return (
          icmp_type,
          code
     )

def get_service_name(port):

    services = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-ALT"  
    }

    return services.get(port, "Unknown")

def get_icmp_description(icmp_type):
     
     descriptions = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded"
     }

     return descriptions.get(
          icmp_type,
          "Other"
     )

def get_tcp_state(syn, ack, fin, rst):

    if syn and not ack:
        return "Connection Start (SYN)"

    elif syn and ack:
        return "Connection Accepted (SYN-ACK)"

    elif fin:
        return "Connection Closing (FIN)"

    elif rst:
        return "Connection Reset (RST)"

    elif ack:
        return "Connection Established"

    return "Unknown"

def format_multi_line(prefix, string, size=16):
     
    size -= len(prefix)

    if isinstance(string, bytes):
        string = ' '.join(
            f'{byte:02X}' for byte in string
        )

    return '\n'.join(
        prefix + string[i:i+size]
        for i in range(0, len(string), size)
    )
    

def main():

    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(3)
    )

    print("=" * 50)
    print("CyberScope v0.9.3")
    print("=" * 50)
    print("Listening for packets ... \n")

    packet_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    unknown_count = 0

    try:

        while True:

            raw_data, address = sock.recvfrom(65535)

            packet_size = len(raw_data)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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

            if ip_protocol == 6:
                tcp_count += 1

            elif ip_protocol == 17:
                udp_count += 1

            elif ip_protocol == 1:
                icmp_count += 1

            else:
                unknown_count += 1

            print("=" * 50)

            print(f"Packet #{packet_count}")
            print(f"Timestamp : {timestamp}")
            print(f"Packet Size : {packet_size} bytes")
            
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
                    offset,
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
                print(f"Source Service : {get_service_name(source_port)}")
                print(f"Dest Service   : {get_service_name(destination_port)}")

                print("Flags")
                print("-" * 20)
                print(f"SYN : {syn}")
                print(f"ACK : {ack}")
                print(f"FIN : {fin}")
                print(f"RST : {rst}")
                print(f"PSH : {psh}")
                print(f"URG : {urg}") 

                print(f"TCP State    : {get_tcp_state(syn, ack, fin, rst)}")

                payload = raw_data[tcp_start + offset:]

                if len(payload) > 0:
                     
                    print()
                    print("Payload")
                    print("-" * 20)

                    print(
                         format_multi_line(
                              "",
                              payload[:64]
                         )
                    )

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
                print(f"Source Service : {get_service_name(source_port)}")
                print(f"Dest Service   : {get_service_name(destination_port)}")
                print(f"Length       : {length}")

            elif ip_protocol == 1:
                 
                icmp_start = 14 + header_length

                icmp_type, code = parse_icmp(
                      raw_data[icmp_start:]
                )

                print()
                print("ICMP")
                print("-" * 20)
                print(f"Type        : {icmp_type}")
                print(f"Code        : {code}")
                print(
                    f"Description : "
                    f"{get_icmp_description(icmp_type)}"
                )

    except KeyboardInterrupt:

        print("\n")

        print("=" * 50)
        print("Statistics")
        print("-" * 20)
        print(f"Total Packets : {packet_count}")
        print(f"TCP           : {tcp_count}")
        print(f"UDP           : {udp_count}")
        print(f"ICMP          : {icmp_count}")
        print(f"Unknown       : {unknown_count}")
        print("=" * 50)

        print("\nProgram terminated.")
                 
if __name__ == "__main__":
    main()