import os
import time
import sys
import subprocess
from hashlib import md5
import platform
import runner

OUTPUT_FILE = "client_file.txt"
time_polling = 0.5

def run_tests(times, cmd_args, csv_file_name):
    csv_file_name = os.path.join("Results", csv_file_name)
    with open(csv_file_name, "wb") as csv_file:
        csv_file.write("Start Time,Time Delta,Bytes Received,MD5" + "\n")

        for i in xrange(times):
            try:
                os.remove(OUTPUT_FILE)
            except:
                pass
            
            start_time = time.time()
            print "Executing:", ' '.join(cmd_args), 'from', platform.node()
            task = subprocess.Popen(cmd_args)
            timeout = 5 * 60
            while task.poll() is None and timeout > 0:
                timeout -= time_polling
                time.sleep(time_polling)
            
            if timeout == 0:
                print "Timeout"
                # Restart servers, and kill client
                runner.restart_servers()
                try:
                    task.kill()
                except OSError:
                    pass

                csv_file.write(str(start_time) + ",0,0,0,timeout\n")
                continue
            
            try:
                with open(OUTPUT_FILE, "rb") as client_file:
                    conts = client_file.read()
            except IOError, e:
                 print "Timeout during connection"
                 continue
            
            end_time = time.time()
            time_delta = end_time - start_time
            
            csv_file.write(str(start_time) + ",")
            csv_file.write(str(time_delta) + ",")
            csv_file.write(str(len(conts)) + ",")
            csv_file.write(md5(conts).hexdigest() + "\n")
            os.system("rm " + OUTPUT_FILE)

def run_quicr(times, csv_file_name):
    cmd_args = [r"Release/quic_client", "--host=10.1.1.3 ", "--port=6121", "--fec", "--max_delay=0", "--lost_bytes_delta=1000", "--lossless", "--fifo"]
    run_tests(times, cmd_args, csv_file_name + "_quicr.csv")

def run_quic(times, csv_file_name):
    cmd_args = [r"Release/quic_client", "--host=10.1.1.3 ", "--port=6122", "--max_delay=0", "--lost_bytes_delta=1000", "--lossless", "--fifo"]
    run_tests(times, cmd_args, csv_file_name + "_quic.csv")

def run_tcp(times, csv_file_name):
    cmd_args = ["python", r"tcp_client.py", "server", "1234", "client_file.txt"]
    run_tests(times, cmd_args, csv_file_name + "_tcp.csv")    

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "Usage: *.py <times to run> <output_csv_file>"
        sys.exit(1)
    
    to_run = ['quic', 'quicr', 'tcp']  
    if len(sys.argv) == 4:
        to_run = sys.argv[3].split(',')

    for f in to_run:
        globals()['run_' + f](int(sys.argv[1]), sys.argv[2])
