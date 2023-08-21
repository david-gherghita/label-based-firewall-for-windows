import pyping

SERVER = 'localhost' #TODO

PACKET_COUNT = 10

r = pyping.ping(SERVER, count = PACKET_COUNT)

if r.packet_lost == 0:
    print('Test passed!')
else:
    print('Test failed!')

print(f'Received {PACKET_COUNT - r.packet_lost} packets out of {PACKET_COUNT}.')