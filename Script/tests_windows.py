import time
import sys
import subprocess
from hashlib import md5

OUTPUT_FILE = "client_file.txt"

def run_tests(times, cmd_args, csv_file_name):
    with open(csv_file_name, "wb") as csv_file:
        csv_file.write("Start Time, Time Delta, Bytes Received, MD5" + "\n")

        for i in xrange(times):
            start_time = time.time()
            
            ret = subprocess.call(cmd_args)
            print ret
            
            with open(OUTPUT_FILE, "rb") as client_file:
                conts = client_file.read()
            end_time = time.time()
            time_delta = end_time - start_time
            print time_delta
            csv_file.write(str(start_time) + ",")
            csv_file.write(str(time_delta) + ",")
            csv_file.write(str(len(conts)) + ",")
            csv_file.write(md5(conts).hexdigest() + "\n")

def run_quicr(times, csv_file_name):
    cmd_args = [r"C:\dev\chromium\src\out\Debug\quic_client.exe", "--host=192.168.14.1", "--port=6121", "--fec", "--max_delay=0", "--lost_bytes_delta=10000", "--lossless", "--fifo"]
    run_tests(times, cmd_args, csv_file_name + "_quicr.csv")

def run_quic(times, csv_file_name):
    cmd_args = [r"C:\dev\chromium\src\out\Debug\quic_client.exe", "--host=192.168.14.1", "--port=6122", "--max_delay=0", "--lost_bytes_delta=10000", "--lossless", "--fifo"]
    run_tests(times, cmd_args, csv_file_name + "_quic.csv")

def run_tcp(times, csv_file_name):
    cmd_args = ["python", r"C:\dev\script\tcp_client.py", "192.168.14.1", "1234", "output_file.txt"]
    run_tests(times, cmd_args, csv_file_name + "_tcp.csv")    

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage: *.py <times to run> <output_csv_file>"
        sys.exit(1)
        md5cm
    run_quicr(int(sys.argv[1]), sys.argv[2])
    #run_quic(int(sys.argv[1]), sys.argv[2])
    #run_tcp(int(sys.argv[1]), sys.argv[2])