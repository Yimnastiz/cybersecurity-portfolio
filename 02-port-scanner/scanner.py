import socket

# Service database 
services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8000: "HTTP-ALT"
}

open_ports = []

def get_service(port):

    if port in services:
        return services[port]
    
    return "Unknown"

def scan_ports(target, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.1)

    try:

        result = sock.connect_ex(
            (target, port)
        )

        if result == 0:
            
            service = get_service(port)

            print(
                f"[+] {port} OPEN ({service})"
            )

            open_ports.append(port)

            try:

                banner = sock.recv(1024)

                banner = banner.decode().strip()

                if banner:

                    print(
                        f"      Banner: {banner}"
                    )
            except:         

             pass

        else:

            pass

    except socket.error:

        print(
            f"Error on {port}"
        )

    finally:

        sock.close()

target = input(
    "Target IP : "
)

start_port = int(
    input("Start Port : ")
)

end_port = int(
    input("End Port : ")
)

print("\n---------------------------")
print(
    f"Scanning {target}"
)
print("---------------------------\n")   

for port in range(
    start_port,
    end_port + 1
):

    scan_ports(
        target,
        port
    )

print("\n---------------------------")

print("Scan Complete")

print(
    f"Open Ports Found: {len(open_ports)}" 
)

print("---------------------------")