import time
import sys
import subprocess
import os
from shutil import copyfile 

# runner dir is home

TEST_FILE = "file%d.txt"

def run_ssh_read_output(endpoint, cmd):
    to_run = "ssh -o StrictHostKeyChecking=no orihiba@%s.QuicTest.QoSoDos \"%s\"" % (endpoint, cmd)
    print "exec: ", to_run
    process = subprocess.Popen(["ssh", "-o", "StrictHostKeyChecking=no", "orihiba@%s.QuicTest.QoSoDos" % endpoint, "\"\"%s\"\"" % cmd], stdout=subprocess.PIPE)
    return process.communicate()[0].strip()

def run_ssh(endpoint, cmd, redirect=None):
    # to_run = "ssh -o StrictHostKeyChecking=no orihiba@%s.QuicTest.QoSoDos \" %s &> /dev/null \" " % (endpoint, cmd)
    if redirect:
        cmd += " &> %s &" % redirect
    to_run = "ssh -o StrictHostKeyChecking=no orihiba@%s.QuicTest.QoSoDos \" %s \" " % (endpoint, cmd)
    print "exec: ", to_run
    return os.system(to_run)


def configure_network(id, server_ip, loss_rate, delay):
    server_name = "server%d" % id   # could use just the ip
    
    eth = run_ssh_read_output(server_name, "ifconfig | grep %s -B 1 | cut -d ' ' -f 1" % server_ip)
    print "interface is %s" % eth
    
    if len(eth.strip()) == 0:
        print "Eth is empty"
        sys.exit(1)
    res = run_ssh(server_name, "sudo tc qdisc add dev %s root netem loss %.1f%% delay %dms" % (eth, loss_rate, delay))
    
    # If already exists
    if res != 0:
        res = run_ssh(server_name, "sudo tc qdisc change dev %s root netem loss %.1f%% delay %dms" % (eth, loss_rate, delay))

        if res != 0:
            print "Error occurred when trying to configure tc. Error = %d" % res
            return -1
        
    return 0

def configure_all(number_of_nodes):
    for id in xrange(number_of_nodes):
        for ep in ["server%d" % id, "client%d" % id]:
            run_ssh(ep, "./sockets.sh &> /dev/null")
    
def kill_clients(id):
    client_name = "client%d" % id
    # run_ssh(client_name, "pkill quic_client")
    # run_ssh(client_name, "pkill python")
    
    run_ssh(client_name, "pkill quic_client; pkill python")
    
def restart_servers(id, m, k):
    server_name = "server%d" % id
    file_name = TEST_FILE % id
    # run_ssh(server_name, "pkill quic_server")
    # run_ssh(server_name, "pkill python")
    # run_ssh(server_name, "cd Release; nohup ./run_servers.sh %s %d %d &>/dev/null; cd .." % (file_name, m, k))
    
    run_ssh(server_name, "pkill quic_server; pkill python; cd Release; nohup ./run_servers.sh %s %d %d &>/dev/null; cd .." % (file_name, m, k))
    time.sleep(1)

def copy_test_file(id, file_size):
    # should_copy_file = False
    file_name = os.path.join("Release", TEST_FILE % id)
    try:
        os.remove(file_name)
    # # If file doesn't exist
    except OSError, e:
        pass
    
    # if should_copy_file:
    print "Copying file"
    wanted_file = os.path.join("Tests", "file_%s.txt" % (file_size))
    copyfile(wanted_file, file_name)
    
    statinfo = os.stat(file_name)
    
    if statinfo.st_size != (file_size * 1024 * 1024):
        raise Exception("Error during file copy")

def run_tests(times, file_name, protocols, server_ip, id, m, k, loss_rate, latency):
    tests_script = os.path.join("tests.py")
    
    run_ssh("client%d" % id, "python %s %d %s %s %d %d %d %f %d %s" % (tests_script, times, file_name, server_ip, id, m, k, loss_rate, latency, protocols), "tests_output_%d.txt" % id)

    
# wait for the first availabe node, remove from in_use and return it
def wait_for_finish(in_use):
    while True:
        for j, i in enumerate(in_use):
            client_name = "client%d" % i
            if len(run_ssh_read_output(client_name, "ps -ef | grep tests | grep -v grep")) == 0:
                print "%s finished running" % client_name 
                # in_use.remove(i)
                in_use = in_use[j+1:] + in_use[:j] # put the scaned in the end, to make scan quicker
                return i, in_use
        time.sleep(10)

        
def get_available_nodes(exclude):
    pool = []
    ips = []
    for i in xrange(0,30):
        if i in exclude:
            ips.append("0.0.0.0")
            continue
        server_name = "server%d" % i
        ip = run_ssh_read_output("client0", "ping %s -c 1 | cut -d '(' -f 2 | cut -d ')' -f 1 | head -n 1" % server_name)
        print ip
        # if no such server
        if len(ip) == 0:
            break
        
        pool.append(i)
        ips.append(ip)
    
    return pool, ips
    
weights_loss = {0:0, 0.9:1, 3:2, 9:3, 30:5, 90:7}
weights_delay = {0:0, 5:2, 50:5, 500:7}
    
def main(loss_rates, latencies, protocols, times, manual_fec, configure, exclude):
    pool, server_ips = get_available_nodes(exclude) # [0, 1, 2], [1.1.1.1, 2.2.2.2, 3.3.3.3]
    available_pool = pool[:]
    
    if configure:
        configure_all(len(pool))
        
    in_use = []
    
    if protocols.endswith("!"):
        protos = protocols[:-1].split(",")
        print "running simultanously on:", protos
        for proto in protos:
            in_use, available_pool = run_simultanously(loss_rates, latencies, proto, times, manual_fec, configure, available_pool, in_use, server_ips)
            print "in_use", in_use
    else:
        in_use, _ = run_simultanously(loss_rates, latencies, protocols, times, manual_fec, configure, available_pool, in_use, server_ips)
    
    while len(in_use) != 0:
        print len(in_use), "clients are still working..", time.ctime(time.time())
        _, in_use = wait_for_finish(in_use)
    
    print "all clients finished.", time.ctime(time.time())
    
def run_simultanously(loss_rates, latencies, protocols, times, manual_fec, configure, available_pool, in_use, server_ips):
    print "in_use:", in_use
    print "available_pool:", available_pool
    
    configurations = [(delay, loss_rate) for delay in latencies for loss_rate in loss_rates]
    for delay, loss_rate in configurations:
        # if protocols == "quic" and (loss_rate, delay) not in [(30.0, 500), (0.9, 250)]:
            # print "skipping", delay, loss_rate
            # continue
        
        # if protocols == "quicr" and (loss_rate, delay) not in [(30.0, 250), (30.0, 0), (30.0, 500), (15.0, 250), (15.0, 500), (0.9, 1000)]:
            # print "skipping", delay, loss_rate
            # continue
        
        # if delay not in [750,1000] and not(protocols == "quicr" and (delay, loss_rate) in [(5, 30.0), (0, 30.0)]):
            # print "skipping", delay, loss_rate
            # continue
        
       
        print "Running with %.1f%%, %dms" % (loss_rate, delay)
      
        file_size = 10
        # file_size = 100
        # weight = weights_loss[loss_rate] * weights_delay[delay]
        
        # if weight < 5:
            # file_size = 100
        # elif weight <= 10:
            # file_size = 20
        # elif weight <= 20:
            # file_size = 10
        # elif weight <= 30:
            # file_size = 5
        # else:
            # file_size = 1
        
        if not manual_fec or protocols != "quicr":
            print "Not Manual FEC"
            left_to_do = [(0, 0)]
        else:
            print "Manual FEC"
            done = [] # don't delete
            
            # if delay != 50 or loss_rate != 15.0:
                # done = [(m, k) for m in xrange(10,250,5) for k in xrange(5,100,5)] # all
            # # else:
                # done = [(m, k) for m in xrange(10,20,5) for k in xrange(5,100,5)] # all
            # # to_do = [(m, k) for m in xrange(3,31) for k in xrange(3,16)] + [(m, k) for m in xrange(50,80,5) for k in xrange(3,16)]
            
            # to_do = [(m, k) for m in xrange(150,250,5) for k in xrange(20,60,5) if m >= k]
            # done = [(m, k) for m in xrange(50,150,5) for k in xrange(20,80,5) if m >= k] + [(m, k) for m in xrange(150,200,5) for k in xrange(30,100,5) if m >= k]
            
            
            # to_do = [(m, k) for m in xrange(200,400,5) for k in xrange(5,200,5) if m >= k]
            
            # if (loss_rate, delay) not in  [(9.0, 750), (9.0, 1000), (30.0, 500)]:
                # done = [(m, k) for m in xrange(10,250,5) for k in xrange(5,100,5)] 
                
            # to_do = [(m, k) for m in xrange(5,255,5) for k in xrange(5,105,5)]
            
            # this
            to_do = [(m, k) for m in xrange(10,250,5) for k in xrange(5,100,5)]
            
            # to_do = [(m, k) for m in xrange(1) for k in xrange(3)]
            
            
            # done = [(m, k) for m in xrange(10,200,5) for k in xrange(5,80,5) if m >= k]
            
                # to_do = [(m, k) for m in xrange(70,100,5) for k in xrange(5,60,5) if m >= k]
                # done = []
                # done = [(m, k) for m in xrange(100,200,10) for k in xrange(40,100,10) if m >= k] + [(m, k) for m in xrange(150,200,10) for k in xrange(40,90,10) if m >= k]
                # to_do = [(m, k) for m in xrange(160,240,5) for k in xrange(20,100,5) if m >= k]
            
                # done = [(m, k) for m in xrange(80,140,10) for k in xrange(30,70,10) if m >= k] + [(m, k) for m in xrange(40,80,10) for k in xrange(10,80,10) if m >= k] + [(m, k) for m in xrange(140,200,10) for k in xrange(10,150,10) if m >= k] + [(m, k) for m in xrange(100,180,5) for k in xrange(10,150,5) if m >= k]
                # done += [(m, k) for m in xrange(100,200,5) for k in xrange(10,150,5) if m >= k]
                # done += [(m, k) for m in xrange(200,220,5) for k in xrange(10,150,5) if m >= k]
                # done += [(m, k) for m in xrange(60,95,5) for k in xrange(10,150,5) if m >= k]
                # to_do = [(m, k) for m in xrange(10,150,5) for k in xrange(5,60,5) if m >= k]
            
            left_to_do = list(set(to_do) - set(done))
            left_to_do.sort()

        
        print "Total test scenarios:", len(left_to_do)
        
        for m, k in left_to_do:
            print "m = %d, k = %d" % (m, k)
            file_name = "%.1f_%d_%d_%d^%d" % (loss_rate, delay, file_size, m, k)
            file_name = file_name.replace(".","-")
            
            # take a pair from available_pool
            if len(available_pool) == 0:
                print "No available node. Waiting.. time: %s" % time.ctime(time.time())
                finished, in_use = wait_for_finish(in_use)
                available_pool.append(finished)

            curr = available_pool.pop(0)
            in_use.append(curr)
            print "now in_use is", in_use
            
            kill_clients(curr)
            restart_servers(curr, m, k)
            copy_test_file(curr, file_size)

            server_ip = server_ips[curr]
            # configure_network(curr, server_ip, loss_rate, delay)
            # time.sleep(5)
            
            time_to_run = times
            # if left_to_do != [(0, 0)]:
                # # we use manual FEC
                # print "times to run becomes 5"
                # time_to_run = 5
            run_tests(time_to_run, file_name, protocols, server_ip, curr, m, k, loss_rate, delay) # should get file id and server ip
        
    print "Finished simultanous run"
    return in_use, available_pool

if __name__ == "__main__":
    loss_rates = [0, 0.9, 3, 9, 30, 90] # percentages. usage: tc qdisc add dev eth0 root netem loss 5%
    latencies = [0, 5, 50, 500] # in ms. usage: tc qdisc add dev eth0 root netem delay 100ms
    protocols = "quic,quicr,tcp"
    times = 10
    configure = True
    exclude = []
    
    if len(sys.argv) != 1:
        if len(sys.argv) != 8:
            print "Usage: *.py <loss_rates> <latencies> <protocols> <times to run> <manual FEC> <should_configure> <exclude_servers>"
            sys.exit(1)
            
        loss_rates = [float(i) for i in sys.argv[1].split(',')]
        latencies  = [int(i) for i in sys.argv[2].split(',')]
        protocols  = sys.argv[3]
        times      = int(sys.argv[4])
        manual_fec   = True if sys.argv[5] == "True" else False
        configure   = True if sys.argv[6] == "True" else False
        exclude  = [int(i) for i in sys.argv[7].split(',')]

    main(loss_rates, latencies, protocols, times, manual_fec, configure, exclude)
    