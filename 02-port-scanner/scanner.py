import socket
target = input("Target IP : ")
port = int(input("Port : "))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

result = sock.connect_ex((target, port))

if result == 0:
    print("Port is OPEN")
else:
    print("Port is CLOSED")

sock.settimeout(1)