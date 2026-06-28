import socket

target = input("Target IP : ")

start_port = int(input("Start Port : "))

end_port = int(input("End Port : "))

print("--------------------")
print(f"Scanning Target : {target}")
print("--------------------")

for port in range(start_port, end_port + 1):
    
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.5)

    result = sock.connect_ex(
        (target, port)
    )

    if result == 0:
        print(f"[+] Port {port} OPEN")
    else:
        print(f"[-] Port {port} CLOSED")

    sock.close()