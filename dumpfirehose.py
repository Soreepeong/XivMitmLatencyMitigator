import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 1234))

while True:
    data = s.recv(int.from_bytes(s.recv(4), "little"))
    direction = int.from_bytes(data[:8], "little")
    xivbundle = data[8:]
    print(direction, xivbundle)
