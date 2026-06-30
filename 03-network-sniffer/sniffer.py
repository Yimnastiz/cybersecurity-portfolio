import socket   

def main():

    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(3)
    )

    print("Waiting for packet . . .\n")

    packet_count = 0
    
    while True:

        raw_data, address = sock.recvfrom(65535)

        packet_count += 1

        print("=" * 50)
        print(f"Packet #{packet_count}")
        print(f"Interface : {address[0]}")
        print(f"Packet Size : {len(raw_data)} bytes")
        print("=" * 50)

if __name__ == "__main__":
    main()