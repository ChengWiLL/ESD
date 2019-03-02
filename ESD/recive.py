#! /usr/bin/python
from scapy.all import *
import logging


def prn(packet):
    llist = []
    for x in range(packet[DNS].ancount):
        llist.append(packet[DNS].an[x].rdata)
    print(packet[DNS].qd.qname.decode('utf-8'))
    return llist


sniff(prn=prn, lfilter=lambda x: x.haslayer(DNS) and x[DNS].an != None and x[DNS].qd.qname.decode('utf-8') == 'baidu.com.')
