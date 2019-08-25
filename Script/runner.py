import time
import sys
import subprocess
import os
from shutil import copyfile 

# runner dir is home

ETH = "eth0"
TEST_FILE = "Release/file.txt"

def run_ssh_read_output(endpoint, cmd):
    to_run = "ssh -o StrictHostKeyChecking=no orihiba@%s.QuicTest.QoSoDos \"%s\"" % (endpoint, cmd)
    print "exec: ", to_run
    process = subprocess.Popen(["ssh", "-o", "StrictHostKeyChecking=no", "orihiba@%s.QuicTest.QoSoDos" % endpoint, "\"\"%s\"\"" % cmd], stdout=subprocess.PIPE)
    return process.communicate()[0].strip()

def run_ssh(endpoint, cmd):
    # to_run = "ssh -o StrictHostKeyChecking=no orihiba@%s.QuicTest.QoSoDos \" %s &> /dev/null \" " % (endpoint, cmd)
    to_run = "ssh -o StrictHostKeyChecking=no orihiba@%s.QuicTest.QoSoDos \" %s \" " % (endpoint, cmd)
    print "exec: ", to_run
    return os.system(to_run)

def configure_network(loss_rate, delay):
    res = run_ssh("server", "sudo tc qdisc add dev %s root netem loss %.1f%% delay %dms" % (ETH, loss_rate, delay))
    
    # If already exists
    if res != 0:
        res = run_ssh("server", "sudo tc qdisc change dev %s root netem loss %.1f%% delay %dms" % (ETH, loss_rate, delay))

        if res != 0:
            print "Error occurred when trying to configure tc. Error = %d" % res
            return -1
        
    return 0

def configure_all():
    global ETH
    for ep in ["server", "client"]:
        run_ssh(ep, "./sockets.sh &> /dev/null")
    ETH = run_ssh_read_output("server", "ifconfig | grep 10.1.1 -B 1 | cut -d ' ' -f 1")
    print "interface is %s" % ETH
    print "done"
    
def kill_clients():
    run_ssh("client", "pkill quic_client")
    run_ssh("client", "pkill python")
    
def restart_servers():       
    run_ssh("server", "pkill quic_server")
    run_ssh("server", "pkill python")
    run_ssh("server", "cd Release; nohup ./run_servers.sh &>/dev/null; cd ..")
    time.sleep(1)

def verify_file_size(file_size):
    should_copy_file = False
    
    try:
        statinfo = os.stat(TEST_FILE)
        print statinfo.st_size

        if statinfo.st_size != (file_size * 1024 * 1024):
            should_copy_file = True
    
    # If file doesn't exist
    except OSError, e:
        should_copy_file = True
    
    if should_copy_file:
        print "Copying file"
        wanted_file = os.path.join("Tests", "file_%s.txt" % (file_size))
        copyfile(wanted_file, TEST_FILE)
        
        statinfo = os.stat(TEST_FILE)
        print "now:", statinfo.st_size
        if statinfo.st_size != (file_size * 1024 * 1024):
            raise Exception("Error during file copy")

def run_tests(times, file_name, protocols):
    tests_script = os.path.join("tests.py")
    run_ssh("client", "python %s %d %s %s" % (tests_script, times, file_name, protocols))

weights_loss = {0:0, 0.9:1, 3:2, 9:3, 30:5, 90:7}
weights_delay = {0:0, 5:2, 50:5, 500:7}
    
def main(loss_rates, latencies, protocols, times):
    configure_all()

    for delay in latencies:
        for loss_rate in loss_rates:
            print "Running with %.1f%%, %dms" % (loss_rate, delay)
            
            file_size = 100
            weight = weights_loss[loss_rate] * weights_delay[delay]
            
            if weight < 5:
                file_size = 100
            elif weight <= 10:
                file_size = 20
            elif weight <= 20:
                file_size = 10
            elif weight <= 30:
                file_size = 5
            else:
                file_size = 1
            
            # if loss_rate == 30 or delay == 50:
                # file_size = 20
            # elif loss_rate == 90 or delay == 500:
                # file_size = 10
            
            file_name = "%.1f_%d_%d" % (loss_rate, delay, file_size)
            file_name = file_name.replace(".","-")
            
            kill_clients()
            restart_servers()
            verify_file_size(file_size)
            configure_network(loss_rate, delay)
            time.sleep(5)
            run_tests(times, file_name, protocols)

if __name__ == "__main__":
    loss_rates = [0, 0.9, 3, 9, 30, 90] # percentages. usage: tc qdisc add dev eth0 root netem loss 5%
    latencies = [0, 5, 50, 500] # in ms. usage: tc qdisc add dev eth0 root netem delay 100ms
    protocols = "quic,quicr,tcp"
    times = 10
    
    if len(sys.argv) != 1:
        if len(sys.argv) != 5:
            print "Usage: *.py <loss_rates> <latencies> <protocols>"
            sys.exit(1)
            
        loss_rates = [float(i) for i in sys.argv[1].split(',')]
        latencies  = [int(i) for i in sys.argv[2].split(',')]
        protocols  = sys.argv[3]
        times      = int(sys.argv[4])

    main(loss_rates, latencies, protocols, times)
    