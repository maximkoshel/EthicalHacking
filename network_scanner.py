#!/usr/bin.env python

# Sending ip addresses on the same network to check who is connected


import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # Sending the IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcasting the IP to everyone
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # Getting only answered list
    clients_list = []

    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMac Address\n-------------------------------------------------------")
    for client in results_list:
        print(client["IP"]+ "\t\t"+ client["MAC"])



scan_result = scan("10.0.2.0/24")
print_result((scan_result))
