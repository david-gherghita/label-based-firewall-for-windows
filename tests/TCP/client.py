import numpy, os, socket, time

SERVER = ("169.254.26.45", 31337) #TODO
MAX_SIZE = 65535

byteSizes = numpy.linspace(1, MAX_SIZE, 10, dtype=int)
connSizes = [1, 3, 6]

index = 0
failed = False
for i in range(len(connSizes)):
    print('Connecting...')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(SERVER)

    for j in range(connSizes[i]):
        word = str(byteSizes[index])
        print(word + (15 - len(word)) * '.', end='')

        bytesToSend = os.urandom(byteSizes[index])

        sock.sendall(bytesToSend)
        time.sleep(1)
        index += 1

        bytesFromServer = b''
        while True:
            try:
                x = sock.recv(MAX_SIZE)
                if not x:
                    break
            except:
                break
            bytesFromServer += x# = sock.recv(MAX_SIZE)
        if bytesToSend == bytesFromServer:
            print("PASS")
        else:
            print('LEN: ' + str(len(bytesToSend)))
            print('LEN: ' + str(len(bytesFromServer)))
            failed = True
            print("FAIL")
    sock.close()

if not failed:
    print('Test passed!')
else:
    print('Test failed!')
