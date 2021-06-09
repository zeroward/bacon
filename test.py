#/usr/bin/env python

from scapy.all import (rdpcap, Dot11, Dot11Beacon, sniff)

ap_list=[]
file=input("Enter a path to the PCAP of interest\n")
pcap=rdpcap(file)

list_dict={}

for packet in pcap:
    if packet.type == 0 and packet.subtype ==8:
        if packet.info not in ap_list:
            ap_list.append(packet.info)
            id_list=[]
            for i in range(0,20):
                try:
                    frame=packet.getlayer(i)
                    id_list.append(frame.ID)
                except:
                    continue
            #print(packet.info)
            #print(id_list)
            list_dict[str(id_list)]=packet.info
print(list_dict)
