from scapy.all import *

send(IP(dst="114.114.114.114")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="baidu.com", qtype='A', qclass='IN')), verbose=0)