import socket   

def main():

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW<
        socket.IPPROTO_IP
    )

    host = input("Local IP Address: ")

    sock.bind((host,0))

    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_HDRINCL,
        1
    )

    print("Waiting for packet . . .\n")

    packet = sock.recvfrom(65535)

    print(packet)

if __name__ == "__main__":
    main()