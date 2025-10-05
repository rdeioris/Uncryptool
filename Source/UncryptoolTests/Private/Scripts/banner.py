import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

s.bind(('127.0.0.1', 0))

s.listen(1)

host, port = s.getsockname()

sys.stdout.write('{}\0'.format(port))
