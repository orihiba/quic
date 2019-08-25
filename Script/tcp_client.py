import sys
import socket
import struct

CHUNK_SIZE = 0x10000000

def receive(ip, port, output_file):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    data_size_raw = s.recv(4)
    data_size = struct.unpack("<I", data_size_raw)[0]
    
    bytes_received = 0
    
    with open(output_file, "wb") as out_file:
        while bytes_received < data_size:
            data = s.recv(CHUNK_SIZE)
            bytes_received += len(data)
            out_file.write(data)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "Usage: *.py <server_ip> <port> <output_file>"
        sys.exit(1)
    
    receive(sys.argv[1], int(sys.argv[2]), sys.argv[3])
