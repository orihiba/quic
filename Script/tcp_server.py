import sys
import socket
import struct
import time
import os.path
import signal
import atexit

CHUNK_SIZE = 0x10000000
curr_socket = None

def serve(input_file):
    global curr_socket
    with open(input_file, "rb") as in_file:
        conts = bytearray(in_file.read())
    conts_len = len(conts)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 1234))
    s.listen(1)
    while True:
        # try:
        client_sock, _ = s.accept()
        curr_socket = client_sock
        # wait for client to confirm network configuration is ready
        v = client_sock.recv(1)
        if v != "V":
            print "Bad response from client: %s", v
        
        len_bytes = struct.pack("<I", conts_len)
        client_sock.send(len_bytes)
        
        bytes_left = conts_len
        print "sending", bytes_left, "bytes"
        while bytes_left > 0:
            bytes_to_send = min(bytes_left, CHUNK_SIZE)
            client_sock.send(str(conts[:bytes_to_send]))
            conts[-bytes_left:-bytes_left + bytes_to_send]
            bytes_left -= bytes_to_send
        # client_sock.shutdown(socket.SHUT_RDWR)
        client_sock.close()

        # except:
            # print "In finally"
            # if curr_socket is not None:
                # curr_socket.shutdown()
                # curr_socket.close()


def handle_exit(a, b):
    print("atexit:", a, b)
    
    if curr_socket is not None:
        curr_socket.shutdown(socket.SHUT_RDWR)
        curr_socket.close()
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: *.py <input_file>"
        sys.exit(1)
    
    # atexit.register(handle_exit)
    # signal.signal(signal.SIGTERM, handle_exit)
    # signal.signal(signal.SIGINT, handle_exit)
    
    serve(sys.argv[1])
