#/usr/bin/env python

from scapy.all import rdpcap
import json
import ast

dict_file="dictionary.txt"
with open(dict_file, 'r') as file:
    temp=file.read()
    try:
        list_dict=ast.literal_eval(temp)
    except:
        list_dict={}
ap_list=[]
file=input("Enter a path to the PCAP of interest\n")
pcap=rdpcap(file)

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
            try:
                print(list_dict[str(id_list)])
            except:
                list_dict[str(id_list)]=packet.info
with open(dict_file, 'w') as file:
    file.write(str(list_dict))
