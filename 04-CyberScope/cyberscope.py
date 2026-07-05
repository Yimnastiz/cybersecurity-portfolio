import socket   
import struct

def main():

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

        packet_count += 1
        print("=" * 50)
        print(f"Packet #{packet_count}")
        print(f"Interface : {address[0]}")
        print(f"Size      : {len(raw_data)} bytes")
        print(f"Source MAC: {source_mac}")
        print(f"Dest MAC  : {destination_mac}")
        print(f"Protocol  : {protocol}")
        print("=" * 50)
        
if __name__ == "__main__":
    main()