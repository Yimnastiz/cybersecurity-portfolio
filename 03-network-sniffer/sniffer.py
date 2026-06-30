import socket   

def main():

    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW<
        socket.ntohs(3)
    )

    host = input("Local IP Address: ")
    
    print("Waiting for packet . . .\n")

    packet = sock.recvfrom(65535)

    print(packet)

if __name__ == "__main__":
    main()