def f():
    l = []
    total_loss_rate = 0
    tot = 0
    for (s,r) in zip(sent,recv):
        cur_tot = s
        l.append(cur_tot)
        tot += cur_tot
        
        if len(l) > 200:
            tot -= l[0]
            l = l[1:]
            
        weight = float(cur_tot) / tot
        curr_loss_rate = (float(s) - float(r)) / s
                
        total_loss_rate = float(total_loss_rate) * (1 - weight) + curr_loss_rate * weight
        
        print total_loss_rate
        