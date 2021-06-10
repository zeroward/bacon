#/usr/bin/env python

from scapy.all import rdpcap
import json
import ast

#Importing dictionary for comparison
dict_file="dictionary.txt"
with open(dict_file, 'r') as file:
    temp=file.read()
    try:
        list_dict=ast.literal_eval(temp)
    except:
        list_dict={}

ap_list=[]
#Getting path for target PCAP from user
file=input("Enter a path to the PCAP of interest\n")
pcap=rdpcap(file)

for packet in pcap:
    if packet.type == 0 and packet.subtype ==8: #If packet is beacon
        if packet.info not in ap_list:          #If SSID has not been parsed
            ap_list.append(packet.info)         #Add SSID to list
            id_list=[]
            for i in range(0,20):               #Iterate through layers. Layers are dynamic but I can't figure out how to get a length of them.
                try:
                    frame=packet.getlayer(i)
                    id_list.append(frame.ID)    #Gets tag number and adds to list
                except:
                    continue
            try:
                print(list_dict[str(id_list)])  #Print firmware version if tag sequence is in dictionary
            except:                             #Tries to get firmware version from user to add to dictionary
                print("Unable to match firmware for ",str(packet.info))
                print("Do you know the firmware for",str(packet.info),"? yes/no" )
                known=input()
                if known == 'yes':
                    version=input("Please enter firmware version\n")
                    list_dict[str(id_list)]=version

with open(dict_file, 'w') as file:
    file.write(str(list_dict))
