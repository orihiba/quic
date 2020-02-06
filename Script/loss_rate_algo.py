def f():
    l = []
    total_loss_rate = 0
    tot = 0
    res = []
    for (s,r) in zip(sent,recv):
        cur_sample = s
        l.append(cur_sample)
        tot += cur_sample
        
        # if len(l) < 100:
            # continue
        
        if len(l) > 100:
            tot -= l[0]
            l = l[1:]

        if tot == 0:
            continue
        
        weight = float(cur_sample) / tot
        curr_loss_rate = (float(s) - float(r)) / s
        
        total_loss_rate_before = total_loss_rate
        total_loss_rate = float(total_loss_rate) * (1 - weight) + curr_loss_rate * weight
        
        # first 7 results are bad
        res += [(total_loss_rate, total_loss_rate_before, curr_loss_rate, weight)]
    return res
        
        
def load():
    global sent
    global recv
    with open(r"C:\dev\Tests\bin\Release\packets_sent.txt", "rb") as f:
        s = f.read()
    with open(r"C:\dev\Tests\bin\Release\packets_received.txt", "rb") as f:
        r = f.read()
        
    sent = [int(i) for i in s.split(",\n")]
    recv = [int(i) for i in r.split(",\n")]

    
load()
for i in f()[0:20]:
    print i