import socket

SERVER = ("localhost", 31337) #TODO
MAX_SIZE = 65507

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
sock.bind(SERVER)

print("UDP server up and listening...")

while(True):
    bytesAddressPair = sock.recvfrom(MAX_SIZE)
    bytes = bytesAddressPair[0]
    addr = bytesAddressPair[1]

    print(f"Received {len(bytes)} byte(s) from {addr}")

    sock.sendto(bytes, addr)
