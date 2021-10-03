import socket
import sys
import argparse

parser = argparse.ArgumentParser('client')
parser.add_argument('server_IP', type=str, help='The IP address of the server')
parser.add_argument('server_port', type=int, help='The port for the server')
parser.add_argument('test_nr', type=int, help='Test number')

args = parser.parse_args()

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = (args.server_IP, args.server_port)
print('connection to {0} port {1}'.format(args.server_IP, args.server_port))
sock.connect(server_address)

try:
    message = 'start test ' + str(args.test_nr)
    sock.sendall(str.encode(message))

    while True:
        data = sock.recv(256)

        if data == b'END':
            break

        print(data.decode("utf-8"))

finally:
    print('Closing client/socket')
    sock.close()
