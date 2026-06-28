import socket
import argparse
import concurrent.futures
import threading


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

lock = threading.Lock()


def get_service(port):

    if port in services:
        return services[port]

    return "Unknown"



def scan_port(target, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.3)


    try:

        result = sock.connect_ex(
            (target, port)
        )


        if result == 0:

            service = get_service(port)

            print(
                f"[+] {port} OPEN ({service})"
            )

            with lock:
                open_ports.append(port)


            try:

                banner = sock.recv(1024)

                banner = banner.decode().strip()


                if banner:

                    print(
                        f"    Banner: {banner}"
                    )


            except:

                pass


    except socket.error:

        print(
            f"Error scanning {port}"
        )


    finally:

        sock.close()



# --------------------
# Argument Setup
# --------------------

parser = argparse.ArgumentParser(
    description="Simple Python Port Scanner"
)


parser.add_argument(
    "-t",
    "--target",
    required=True,
    help="Target IP address"
)


parser.add_argument(
    "-s",
    "--start",
    required=True,
    type=int,
    help="Starting port"
)


parser.add_argument(
    "-e",
    "--end",
    required=True,
    type=int,
    help="Ending port"
)


args = parser.parse_args()



target = args.target

start_port = args.start

end_port = args.end



print("--------------------")
print(
    f"Scanning {target}"
)
print("--------------------")



with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    
    futures = []

    for port in range(start_port, end_port + 1):

       futures.append(
            executor.submit(
                scan_port,
                target,
                port
            )
        )

    for future in concurrent.futures.as_completed(futures):
        future.result()

print("--------------------")
print("Scan Complete")

print(
    f"Open Ports: {len(open_ports)}"
)

print("--------------------")