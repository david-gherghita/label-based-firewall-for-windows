import socket

SERVER = ("localhost", 31337) #TODO
MAX_SIZE = 65535

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
sock.bind(SERVER)

print("TCP server up and listening...")

while True:
    sock.listen()
    conn, addr = sock.accept()
    print(f"Received connection from {addr}")

    while True:
        bytes = conn.recv(MAX_SIZE)
        if not bytes:
            break
        print(f"Received {len(bytes)} byte(s)")
        #conn.sendall(bytes)
