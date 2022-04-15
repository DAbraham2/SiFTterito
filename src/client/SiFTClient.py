import socket
import sys

HOST, PORT = 'localhost', 5150

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    sock.sendall(bytes("fasztapicsadba", "utf-8"))
    received = str(sock.recv(1024), "utf-8")
    sock.sendall(bytes('feri', "utf-8"))
    received2 = str(sock.recv(1024), "utf-8")

print('Sent:        {}'.format("fasztapicsadba"))
print('Received:    {}'.format(received))