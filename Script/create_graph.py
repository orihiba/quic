import sys
import math
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import itertools
from pylab import rcParams
rcParams['figure.figsize'] = 11, 7
rcParams['figure.dpi'] = 150

loss_rates = [0, 0.9, 3, 9, 15, 30]
latencies = [0, 5 ,50, 250, 500, 750, 1000]
protos = ["tcp", "quic", "quicr"]
colors = {'tcp' : 'r', 'quic' : 'b', 'quicr' : 'g'}
markers = {'tcp' : '.', 'quic' : '+', 'quicr' : '*'}
lines = {'tcp' : '--', 'quic' : ':', 'quicr' : '-'}

tcp_data = {}
quic_data = {}
quicr_data = {}


def parse_data(input_file):
    with open(input_file, "rb") as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines):
        if i == 0:
            continue # skip titles

        proto, loss, latency, time_, sd, runs, success = line.split(',')[:7]
        
        # each key is a tuple of (loss rate, latency)
        # each value is a tuple of (average time, standard deviation)
        globals()[proto + "_data"][(float(loss), int(latency))] = (float(time_), float(sd))

        
def create_1000ms_graph():
    for proto in protos:
        x = []
        y = []
        sd = []

        for i, loss in enumerate(loss_rates):
            sample = globals()[proto + "_data"][(loss, 1000)]
            time_ = sample[0]
            if time_ == 0:
                continue # timeout
            
            x += [i] #[loss]    
            y += [sample[0]]
            sd += [sample[1]]
        
        plt.errorbar(x , y, sd, linestyle=lines[proto], marker=markers[proto], fmt='--' + colors[proto], label=proto)
        plt.legend(loc='best')

    plt.plot(3.975, 600, marker='x',color=colors['tcp'])
    plt.plot(4.975, 600, marker='x',color=colors['tcp'])

    plt.plot(3, 600, marker='x',color=colors['quic'])
    plt.plot(4.025, 600, marker='x',color=colors['quic'])
    plt.plot(5.025, 600, marker='x',color=colors['quic'])

    plt.xticks(np.arange(len(loss_rates)), loss_rates)
    plt.yticks([0,100,200,300,400,500,600], [0,100,200,300,400,500,'(Timeout) 600'])
    
    plt.xlabel('Loss rate (%)')
    plt.ylabel('Time (seconds)')     
      
    plt.grid(True, linestyle="dashed")
    plt.savefig("graph_1000ms.pdf")
    plt.show() 
    plt.close()

    
def create_30loss_graph():
    for proto in protos:
        x = []
        y = []
        sd = []

        for i, latency in enumerate(latencies):
            sample = globals()[proto + "_data"][(30.0, latency)]
            time_ = sample[0]
            if time_ == 0:
                continue # timeout
            
            x += [i] #[latency]    
            y += [sample[0]]
            sd += [sample[1]]
        
        plt.errorbar(x , y, sd, linestyle=lines[proto], marker=markers[proto], fmt='--' + colors[proto], label=proto)
        plt.legend(loc='best')
    
    plt.xticks(np.arange(len(latencies)), latencies)
    plt.yticks([0,100,200,300,400,500,600], [0,100,200,300,400,500,'(Timeout) 600'])

    plt.plot(2.975, 600, marker='x',color=colors['tcp'])
    plt.plot(3.975, 600, marker='x',color=colors['tcp'])
    plt.plot(4.975, 600, marker='x',color=colors['tcp'])
    plt.plot(5.975, 600, marker='x',color=colors['tcp'])

    plt.plot(3.025, 600, marker='x',color=colors['quic'])
    plt.plot(4.025, 600, marker='x',color=colors['quic'])
    plt.plot(5.025, 600, marker='x',color=colors['quic'])
    plt.plot(6.025, 600, marker='x',color=colors['quic'])

    plt.xlabel('Latency (milliseconds)')
    plt.ylabel('Time (seconds)')     
    
    plt.grid(True, linestyle="dashed")
    plt.savefig("graph_30_loss.pdf")
    plt.show()
    plt.close()
    
    
def create_tcp_quicr_ratio_graph():
    colors2 = {0 : 'r', 0.9 : 'b', 3 : 'g', 9 : 'm'}
    markers2 = {0 : '.', 0.9 : '+', 3 : '*', 9 : 'o'}
    lines2 = {0 : '--', 0.9 : ':', 3 : '-', 9 : '-.'}
    
    
    for loss in [0, 0.9, 3, 9]:
        x = []
        y = []
        for i, latency in enumerate(latencies):
            sample_tcp = tcp_data[(loss, latency)]
            sample_quicr = quicr_data[(loss, latency)]
            
            if sample_tcp[0] == 0 or sample_quicr[0] == 0:
                continue # timeout
            
            x += [i] #[latency]
            y += [sample_tcp[0] / sample_quicr[0]]
        
        plt.errorbar(x, y, linestyle=lines2[loss], marker=markers2[loss], fmt='--' + colors2[loss], label=str(loss) + "%")
        plt.legend(loc='best')
    
    plt.xticks(np.arange(len(latencies)), latencies)
    # plt.yticks([0,100,200,300,400,500,600], [0,100,200,300,400,500,'(Timeout) 600'])

    # plt.plot(2.975, 600, marker='x',color=colors['tcp'])
    # plt.plot(3.975, 600, marker='x',color=colors['tcp'])
    # plt.plot(4.975, 600, marker='x',color=colors['tcp'])
    # plt.plot(5.975, 600, marker='x',color=colors['tcp'])

    # plt.plot(3.025, 600, marker='x',color=colors['quic'])
    # plt.plot(4.025, 600, marker='x',color=colors['quic'])
    # plt.plot(5.025, 600, marker='x',color=colors['quic'])
    # plt.plot(6.025, 600, marker='x',color=colors['quic'])

    plt.xlabel('Latency L (milliseconds)')
    plt.ylabel('Time ratio r(L) tcp/quicr')     
    
    plt.grid(True, linestyle="dashed")
    plt.savefig("graph_tcp_quicr_ratio.pdf")
    plt.show()
    plt.close()
    
def main(input_file):
    parse_data(input_file)
    create_1000ms_graph()
    create_30loss_graph()
    create_tcp_quicr_ratio_graph()
    
if __name__ == '__main__':
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        main('final_results.csv')
