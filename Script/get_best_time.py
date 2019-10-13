import os
import sys

def main(dir):
    for root, dirs, files in os.walk(dir):
        if "bad" in root:
            continue
        items = []
        avg_items = []
        for f_name in files:
            with open(os.path.join(root, f_name), "rb") as f:
                c = f.read()
            x = [i.split(",") for i in c.splitlines()[1:]]          
            
            times = [float(i[2]) for i in x if i[2] != '0']
            if len(times) > 0:
                # print f_name, times
                items.append((min(times), f_name))                
                avg_items.append((float(sum(times)) / len(times), f_name))
        
        min_time = min(items, key=lambda item:item[0])
        min_avg_time = min(avg_items, key=lambda item:item[0])
        
        avg_items.sort(key= lambda item: item[0])
        for item in avg_items[::-1]:
            print item
        
        print "min_time is", min_time
        print "min_avg_time is", min_avg_time
        
        
        
if __name__ == '__main__':
    main(sys.argv[1])