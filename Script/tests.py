import os
import time
import sys
import subprocess
from hashlib import md5
import platform
import runner

OUTPUT_FILE = "client_file_%s.txt"
CONNECTION_FILE = "Release/connection_file_%s.txt"
time_polling = 0.5

def run_tests(times, cmd_args, csv_file_name, server_ip, file_name, connection_file, id, m, k, loss_rate, latency):
    csv_file_name = os.path.join("Results", csv_file_name)
    with open(csv_file_name, "wb", buffering=0) as csv_file:
        csv_file.write("Start Time,Time To Connect,Connection Time,Bytes Received,MD5" + "\n")
        first_run = True
        
        for i in xrange(times):
            try:
                os.remove(file_name)
            except:
                pass
            
            try:
                os.remove(connection_file)
            except:
                pass
            
            # The connection should be with no network special configuration
            runner.configure_network(id, server_ip, 0, 0)
            runner.restart_servers(id, m, k)
            
            if not first_run and "tcp" in cmd_args[1]:
                time.sleep(2 * 60) # wait until server port is closed
                runner.restart_servers(id, m, k)
            first_run = False
            
            start_time = time.time()
            print "Executing:", ' '.join(cmd_args), 'from', platform.node()
            task = subprocess.Popen(cmd_args)
            
            print "Waiting for connection"
            # Wait for connection (the CLIENT should create it)
            connection_timeout = 20 # 20 seconds to connect with no obsticles... should be enough
            while not os.path.exists(connection_file) and connection_timeout > 0:
                # print "File does not exist"
                time.sleep(0.1)
                connection_timeout -= 0.1
            
            if connection_timeout <= 0:
                # this server machine is faulted. 
                print "Bad server. run again for %s" % (csv_file_name,)
                while True:
                    pass
            
            
            # Conencted
            print "Connection confirmed"
            connection_time = time.time()
            
            runner.configure_network(id, server_ip, loss_rate, latency)
            
            # delete connection file
            os.remove(connection_file)
            print "Deleted connection file"
            
            # Wait for the client to finish
            timeout = 10 * 60
            if times == 5:
                timeout = 3 * 60
                if latency < 750:
                    timeout = 2 * 60
            
            while task.poll() is None and timeout > 0:
                print "Waiting"
                timeout -= time_polling
                time.sleep(time_polling)
            
            print "task ended"
            
            if timeout == 0:
                print "Timeout"
                # Restart servers, and kill client
                runner.restart_servers(id, m, k)
                try:
                    task.kill()
                except OSError:
                    pass

                csv_file.write("%.1f,%.1f,0,0,0,timeout\n" % (start_time, connection_time - start_time))
                continue
            
            try:
                with open(file_name, "rb") as client_file:
                    conts = client_file.read()
            except IOError, e:
                 print "Timeout during connection"
                 continue
            
            end_time = time.time()
            time_delta = end_time - connection_time
            
            csv_file.write(str(start_time) + ",")
            csv_file.write(str(connection_time - start_time) + ",")
            csv_file.write(str(time_delta) + ",")
            csv_file.write(str(len(conts)) + ",")
            csv_file.write(md5(conts).hexdigest() + "\n")
            # os.system("rm " + file_name)

def run_quicr(times, csv_file_name, server_ip, file_name, connection_file, id, m, k, loss_rate, latency):
    cmd_args = [r"Release/quic_client", "--host=%s" % server_ip, "--port=6121", "--fec", "--max_delay=0", "--lost_bytes_delta=1000", "--lossless", "--fifo", "--output_file=%s" % file_name, "--connection_file=%s" % connection_file, "--k=%d" % k, "--m=%d" % m]
    run_tests(times, cmd_args, csv_file_name + "_quicr.csv", server_ip, file_name, connection_file, id, m, k, loss_rate, latency)

def run_quic(times, csv_file_name, server_ip, file_name, connection_file, id, m, k, loss_rate, latency):
    cmd_args = [r"Release/quic_client", "--host=%s" % server_ip, "--port=6122", "--max_delay=0", "--lost_bytes_delta=1000", "--lossless", "--fifo", "--output_file=%s" % file_name, "--connection_file=%s" % connection_file]
    run_tests(times, cmd_args, csv_file_name + "_quic.csv", server_ip, file_name, connection_file, id, m, k, loss_rate, latency)

def run_tcp(times, csv_file_name, server_ip, file_name, connection_file, id, m, k, loss_rate, latency):
    cmd_args = ["python", r"tcp_client.py", server_ip, "1234", file_name, connection_file]
    run_tests(times, cmd_args, csv_file_name + "_tcp.csv", server_ip, file_name, connection_file, id, m, k, loss_rate, latency)

if __name__ == "__main__":
    if len(sys.argv) < 9:
        print "Usage: *.py <times to run> <output_csv_file> <server_ip> <file_id> <m> <k> <loss_rate> <latency>"
        sys.exit(1)
    
    to_run = ['quic', 'quicr', 'tcp']  
    if len(sys.argv) == 10:
        to_run = sys.argv[9].split(',')
    for f in to_run:
        globals()['run_' + f](int(sys.argv[1]), sys.argv[2], sys.argv[3], OUTPUT_FILE % sys.argv[4], CONNECTION_FILE % sys.argv[4], int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]), float(sys.argv[7]), int(sys.argv[8]))
