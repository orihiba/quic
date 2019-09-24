import os
import time
import sys
import subprocess
from hashlib import md5
import platform
import runner

OUTPUT_FILE = "client_file_%s.txt"
time_polling = 0.5

def run_tests(times, cmd_args, csv_file_name, file_name, id, m, k):
    csv_file_name = os.path.join("Results", csv_file_name)
    with open(csv_file_name, "wb", buffering=0) as csv_file:
        csv_file.write("Start Time,Time Delta,Bytes Received,MD5" + "\n")

        for i in xrange(times):
            # try:
                # os.remove(OUTPUT_FILE)
            # except:
                # pass
            
            start_time = time.time()
            print "Executing:", ' '.join(cmd_args), 'from', platform.node()
            task = subprocess.Popen(cmd_args)
            timeout = 3 * 60
            while task.poll() is None and timeout > 0:
                timeout -= time_polling
                time.sleep(time_polling)
            
            if timeout == 0:
                print "Timeout"
                # Restart servers, and kill client
                runner.restart_servers(id, m, k)
                try:
                    task.kill()
                except OSError:
                    pass

                csv_file.write(str(start_time) + ",0,0,0,timeout\n")
                continue
            
            try:
                with open(file_name, "rb") as client_file:
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
            # os.system("rm " + file_name)
            os.remove(file_name)
            runner.restart_servers(id, m, k)

def run_quicr(times, csv_file_name, server_ip, file_name, id, m, k):
    cmd_args = [r"Release/quic_client", "--host=%s" % server_ip, "--port=6121", "--fec", "--max_delay=0", "--lost_bytes_delta=1000", "--lossless", "--fifo", "--output_file=%s" % file_name, "--k=%d" % k, "--m=%d" % m]
    run_tests(times, cmd_args, csv_file_name + "_quicr.csv", file_name, id, m, k)

def run_quic(times, csv_file_name, server_ip, file_name, id, m, k):
    cmd_args = [r"Release/quic_client", "--host=%s" % server_ip, "--port=6122", "--max_delay=0", "--lost_bytes_delta=1000", "--lossless", "--fifo", "--output_file=%s" % file_name]
    run_tests(times, cmd_args, csv_file_name + "_quic.csv", file_name, id, m, k)

def run_tcp(times, csv_file_name, server_ip, file_name, id, m, k):
    cmd_args = ["python", r"tcp_client.py", server_ip, "1234", file_name]
    run_tests(times, cmd_args, csv_file_name + "_tcp.csv", file_name, id, m, k)

if __name__ == "__main__":
    if len(sys.argv) < 7:
        print "Usage: *.py <times to run> <output_csv_file> <server_ip> <file_id> <m> <k>"
        sys.exit(1)
    
    to_run = ['quic', 'quicr', 'tcp']  
    if len(sys.argv) == 8:
        to_run = sys.argv[7].split(',')
    for f in to_run:
        globals()['run_' + f](int(sys.argv[1]), sys.argv[2], sys.argv[3], OUTPUT_FILE % sys.argv[4], int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]))
