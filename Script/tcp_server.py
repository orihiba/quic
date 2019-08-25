import sys
import socket
import struct

CHUNK_SIZE = 0x10000000

def serve(input_file):
    with open(input_file, "rb") as in_file:
        conts = bytearray(in_file.read())
    conts_len = len(conts)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 1234))
    s.listen(1)
    while True:
        client_sock, _ = s.accept()
        len_bytes = struct.pack("<I", conts_len)
        client_sock.send(len_bytes)
        
        bytes_left = conts_len
        print "sending", bytes_left, "bytes"
        while bytes_left > 0:
            bytes_to_send = min(bytes_left, CHUNK_SIZE)
            client_sock.send(str(conts[:bytes_to_send]))
            conts[-bytes_left:-bytes_left + bytes_to_send]
            bytes_left -= bytes_to_send

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: *.py <input_file>"
        sys.exit(1)
    
    serve(sys.argv[1])
