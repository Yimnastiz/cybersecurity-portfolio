import socket

def scan_port(target, port):
    
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.5)

    try:

        result = sock.connect_ex(
            (target, port)
        )

        if result == 0:

            print(f"[+] Port {port} OPEN")

            try:

                banner = sock.recv(1024)

                print(
                    f"     Banner: {banner.decode().strip()}"
                )
            
            except:

                print(
                    "     Banner: No response"
                )

            else:

                print(
                    f"[-] Port {port} CLOSED"
                )

    except socket.error:

        print(
            f"Error connecting port {port}"
        )

    finally:

        sock.close()

target = input("Target IP : ")

start_port = int(
    input("Start Port : ")
)

end_port = int(
    input("End Port : ")
)

print("---------------------")
print(
    f"Scanning {target}"
)
print("---------------------")

for port in range(
    start_port,
    end_port + 1
):
    
    scan_port(
        target,
        port
    )