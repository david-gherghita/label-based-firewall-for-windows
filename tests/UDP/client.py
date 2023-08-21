import numpy, os, socket

SERVER = ("localhost", 31337) #TODO
MAX_SIZE = 65507

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

byteSizes = numpy.linspace(1, MAX_SIZE, 10, dtype=int)

failed = False
for i in range(len(byteSizes)):
    word = str(byteSizes[i])
    print(word + (15 - len(word)) * '.', end='')

    bytesToSend = os.urandom(byteSizes[i])
    sock.sendto(bytesToSend, SERVER)

    bytesFromServer = sock.recvfrom(MAX_SIZE)[0]
    if bytesToSend == bytesFromServer:
        print("PASS")
    else:
        failed = True
        print("FAIL")

if not failed:
    print('Test passed!')
else:
    print('Test failed!')
