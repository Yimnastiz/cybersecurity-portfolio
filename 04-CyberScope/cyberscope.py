import socket   

def main():

    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(3)
    )

    print("=" * 40)
    print("CyberScope v0.1")
    print("=" * 40)
    print("Listening for packets ... \n")

    packet_count = 0

    while True:

        raw_data, address = sock.recvfrom(65535)

        packet_count += 1
        print(f"[{packet_count}] "
              f"Interface: {address[0]} |"
              f"Size: {len(raw_data)} bytes")
        
if __name__ == "__main__":
    main()