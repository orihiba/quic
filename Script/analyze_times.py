import os
import sys
import re
import operator

OUTPUT = "output.csv"

def main(dir):
    results = []

    for root, dirs, files in os.walk(dir):
        if "bad" in root:
            continue
        items = []
        avg_items = []
        for f_name in files:
            # print f_name
            loss_rate, latency, file_size, fec_conf, protocol = re.search("(\d+\-\d+)_(\d+)_(\d+)_(\d+\^\d+)_(\w+).csv" , f_name).groups()
            loss_rate = loss_rate.replace('-', '.')
            # print loss_rate, latency, file_size, fec_conf, protocol
        
            with open(os.path.join(root, f_name), "rb") as f:
                c = f.read()
            x = [i.split(",") for i in c.splitlines()[1:]]
            
            times = [float(i[2]) for i in x if i[2] != '0']
            success_runs = len(times)
            
            if success_runs == 0:
                avg = 0
                standard_deviation = 0
            else:
                avg = float(sum(times)) / len(times)
                total = sum([pow(i - avg, 2) for i in times])
                variance = total / len(times)
                standard_deviation = pow(variance, 0.5)
            
            record = [protocol, loss_rate, latency, str(avg), str(standard_deviation), str(success_runs), "V" if success_runs >= 5 else "X"]
            results.append(record)
            
            # print record

    results = sorted(results, key = operator.itemgetter(1, 2, 0))
            
    with open(OUTPUT, "wb") as output:
        output.write("Protocol,Loss Rate,Latency,Time,Standard Deviation,Success Runs,Pass" + "\n")

        for record in results:
            # print record
            output.write(','.join(record))
            output.write('\n')
        
        
if __name__ == '__main__':
    main(sys.argv[1])