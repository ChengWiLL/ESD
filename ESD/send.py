from scapy.all import *
import asyncio
from itertools import islice
import multiprocessing

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
root_domain = 'python.org'
remainder = 0
data = {}

def limited_concurrency_coroutines(coros, limit):
        futures = [
            asyncio.ensure_future(c)
            for c in islice(coros, 0, limit)
        ]

        async def first_to_finish():
            while True:
                await asyncio.sleep(0)
                for f in futures:
                    if f.done():
                        futures.remove(f)
                        try:
                            nf = next(coros)
                            futures.append(asyncio.ensure_future(nf))
                        except StopIteration:
                            pass
                        return f.result()

        while len(futures) > 0:
            yield first_to_finish()

async def start(tasks):
    """
    Limit the number of coroutines for reduce memory footprint
    :param tasks:
    :return:
    """
    for res in limited_concurrency_coroutines(tasks, 100):
        await res

async def query(line):
    # root domain
    if line == '@' or line == '':
        sub_domain = root_domain
    else:
        sub = ''.join(line.rsplit(root_domain, 1)).rstrip('.')
        sub_domain = '{sub}.{domain}'.format(sub=line, domain=root_domain)
    try:
        send(IP(dst="114.114.114.114")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=sub_domain, qtype='A', qclass='IN')), verbose=0)
    except Exception as e:
        pass

def recive(count):
    def prn(packet):
        qname = packet[DNS].qd.qname.decode('utf-8')
        global remainder
        remainder += 1
        if len(qname.rsplit(root_domain, 1)) > 1 and packet[DNS].an != None:
            llist = []
            for x in range(packet[DNS].ancount):
                llist.append(packet[DNS].an[x].rdata)
            data[qname] = llist
        #print(remainder)
    
    sniff(count=count, prn=prn, lfilter=lambda x: x.haslayer(DNS))
    print(remainder)
    


with open('./subs-test.esd') as f:
    t = multiprocessing.Process(target=recive, args=[25])
    t.start()
    task = (query(line.strip()) for line in f)
    loop.run_until_complete(start(task))

