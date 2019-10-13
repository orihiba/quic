import sys
import socket
import struct
import os.path
import time

CHUNK_SIZE = 0x10000000

def receive(ip, port, output_file, connection_file):
    # print "tcp_client: Connecting"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    # print "tcp_client: Connected"
    
    # conencted, create the "wait for connection" file
    with open(connection_file, "wb") as f:
        pass
    # print "tcp_client: Created file"
    
    # wait for the file to be deleted by test script
    while os.path.exists(connection_file):
        time.sleep(0.1)
    # print "Connection file deleted, Continue transmitting file (sending ack to server)"
    s.send("V")

    data_size_raw = s.recv(4)
    data_size = struct.unpack("<I", data_size_raw)[0]
    # print "tcp_client: Recev file size"
    bytes_received = 0
    
    with open(output_file, "wb") as out_file:
        while bytes_received < data_size:
            data = s.recv(CHUNK_SIZE)
            print "tcp_client: recv chunk"
            bytes_received += len(data)
            out_file.write(data)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print "Usage: *.py <server_ip> <port> <output_file> <connection_file>"
        sys.exit(1)
    
    receive(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4])
