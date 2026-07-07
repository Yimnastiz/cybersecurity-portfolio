import socket   
import struct
import datetime
import argparse

from colorama import (
    Fore,
    Style,
    init
)

init(autoreset=True)

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

def get_packet_direction(source_ip, destination_ip, local_ip):
     
    if source_ip == local_ip:
        return "Outgoing"

    elif destination_ip == local_ip:
        return "Incoming"

    return "Forwarded / Unknown"

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

def format_ascii(data):

    output = ""

    for byte in data:

        if 32 <= byte <= 126:
            output += chr(byte)

        else:
            output += "."

    return output   

def hex_ascii_dump(data, width=16):

    for i in range(0, len(data), width):

        chunk = data[i:i+width]

        hex_part = ' '.join(
            f'{byte:02X}'
            for byte in chunk
        )

        ascii_part = ""

        for byte in chunk:

            if 32 <= byte <= 126:
                ascii_part += chr(byte)
            else:
                ascii_part += "."

        
        line = (
            Fore.YELLOW +
            f"{i:04X}  "
            + Fore.CYAN +
            f"{hex_part:<48} "
            + Fore.GREEN +
            ascii_part
        )

        log(line)

def parse_arguments():

    parser = argparse.ArgumentParser(
        description="CyberScope Packet Analyzer"
    )

    parser.add_argument(
        "--tcp",
        action="store_true",
        help="Show TCP packets only"
    )

    parser.add_argument(
        "--udp",
        action="store_true",
        help="Show UDP packets only"
    )

    parser.add_argument(
        "--icmp",
        action="store_true",
        help="Show ICMP packets only"
    )

    parser.add_argument(
        "--port",
        type=int,
        help="Filter by port"
    )

    parser.add_argument(
        "--ip",
        help="Filter by IP address"
    )

    parser.add_argument(
        "--save",
        help="Save captured packets to file"
    )

    return parser.parse_args()

log_file = None

def log(text):

    print(text)

    if log_file:
        log_file.write(text + "\n")

def get_tcp_flags(syn, ack, fin, rst, psh, urg):

    flags = []

    if syn:
        flags.append("SYN")

    if ack:
        flags.append("ACK")

    if fin:
        flags.append("FIN")

    if rst:
        flags.append("RST")

    if psh:
        flags.append("PSH")

    if urg:
        flags.append("URG")

    if not flags:
        return "NONE"

    return ", ".join(flags)

def packet_summary(
    protocol,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    packet_size,
    syn=False,
    ack=False,
    fin=False,
    rst=False,
    psh=False,
    urg=False
):

    flags = []

    if syn:
        flags.append("SYN")

    if ack:
        flags.append("ACK")

    if psh:
        flags.append("PSH")

    if fin:
        flags.append("FIN")

    if rst:
        flags.append("RST")

    if urg:
        flags.append("URG")

    flag_text = ",".join(flags)

    return (
        f"[{protocol}] "
        f"{source_ip}:{source_port} -> "
        f"{destination_ip}:{destination_port} "
        f"[{flag_text}] "
        f"{packet_size} Bytes"
    )

def main():

    args = parse_arguments()

    global log_file

    if args.save:
        log_file = open(args.save, "w")

    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(3)
    )

    print(Fore.CYAN + "=" * 50)
    print(Fore.GREEN + Style.BRIGHT + "CyberScope v0.9.6")
    print(Fore.CYAN + "=" * 50)
    print(Fore.YELLOW + "Listening for packets...\n")

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

            local_ip = address[0]

            protocol_name = get_protocol_name(ip_protocol)

            if args.ip:
                if (
                    source_ip != args.ip and
                    destination_ip != args.ip
                ):
                    continue

            if args.tcp and ip_protocol != 6:
                continue

            if args.udp and ip_protocol != 17:
                continue

            if args.icmp and ip_protocol != 1:
                continue
    
            packet_count += 1

            if ip_protocol == 6:
                tcp_count += 1

            elif ip_protocol == 17:
                udp_count += 1

            elif ip_protocol == 1:
                icmp_count += 1

            else:
                unknown_count += 1

            
            print(Fore.CYAN + "=" * 50)
            log(Fore.GREEN + f"Packet #{packet_count}")
            log(f"Timestamp : {timestamp}")
            log(f"Packet Size : {packet_size} bytes")
            
            print()
            
            print(Fore.YELLOW + "Ethernet")
            print(Fore.YELLOW + "-" * 20)

            log(f"Source MAC : {Fore.GREEN}{source_mac}")
            log(f"Dest MAC   : {Fore.GREEN}{destination_mac}")

            print()

            print(Fore.BLUE + "IPv4")
            print(Fore.BLUE + "-" * 20)

            log(f"Version      : {version}")
            log(f"Header Len   : {header_length}")
            log(f"TTL          : {ttl}")

            log(
                f"Protocol     : "
                f"{Fore.MAGENTA}{protocol_name}"
                f"{Style.RESET_ALL} ({ip_protocol})"
            )

            log(f"Source IP    : {Fore.CYAN}{source_ip}")
            log(f"Dest IP      : {Fore.CYAN}{destination_ip}")

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

                direction = get_packet_direction(
                    source_ip,
                    destination_ip,
                    local_ip
                )

                flag_text = get_tcp_flags(
                    syn,
                    ack,
                    fin,
                    rst,
                    psh,
                    urg
                )

                if args.port:

                    if (
                        source_port != args.port and
                        destination_port != args.port
                    ):
                        continue

                log()

                log(
                    Fore.CYAN +
                    f"[{protocol_name}] "
                    + Fore.GREEN +
                    f"{source_ip}:{source_port}"
                    + Fore.WHITE +
                    "  -->  "
                    + Fore.YELLOW +
                    f"{destination_ip}:{destination_port}"
                )

                log(
                    Fore.MAGENTA +
                    f"Direction : {direction}"
                )

                log(
                    Fore.BLUE +
                    f"Flags : [{flag_text}]"
                )

                log()

                print()
                summary = packet_summary(
                    protocol_name,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    packet_size,
                    syn,
                    ack,
                    fin,
                    rst,
                    psh,
                    urg
                )

                print(Fore.LIGHTWHITE_EX + Style.BRIGHT + summary)
                if log_file:
                    log_file.write(summary + "\n")
                    
                print(Fore.RED + "TCP")
                print(Fore.RED + "-" * 20)
                log(f"Source Port   : {source_port}")
                log(f"Dest Port     : {destination_port}")

                log(
                    f"Source Service : "
                    f"{Fore.GREEN}{get_service_name(source_port)}"
                )

                log(
                    f"Dest Service   : "
                    f"{Fore.GREEN}{get_service_name(destination_port)}"
                )
                
                print()
                log("Flags")
                log("-" * 20)
                log(f"SYN : {syn}")
                log(f"ACK : {ack}")
                log(f"FIN : {fin}")
                log(f"RST : {rst}")
                log(f"PSH : {psh}")
                log(f"URG : {urg}") 

                state = get_tcp_state(syn, ack, fin, rst)

                

                color = Fore.WHITE

                if "Established" in state:
                    color = Fore.GREEN

                elif "Start" in state:
                    color = Fore.YELLOW

                elif "Accepted" in state:
                    color = Fore.CYAN

                elif "Closing" in state:
                    color = Fore.MAGENTA

                elif "Reset" in state:
                    color = Fore.RED

                log(f"TCP State : {color}{state}")

                payload = raw_data[tcp_start + offset:]

                if len(payload) > 0:
                     
                    log("")
                    log(Fore.MAGENTA + "Payload")
                    log(Fore.MAGENTA + "-" * 20)
       
                    hex_ascii_dump(payload[:64])

                    log("")

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

        log("\n")

        log("=" * 50)
        log("Statistics")
        log("-" * 20)
        log(f"Total Packets : {packet_count}")
        log(f"TCP           : {tcp_count}")
        log(f"UDP           : {udp_count}")
        log(f"ICMP          : {icmp_count}")
        log(f"Unknown       : {unknown_count}")
        log("=" * 50)

        if log_file:
            log_file.close()

        print("\nProgram terminated.")
                 
if __name__ == "__main__":
    main()