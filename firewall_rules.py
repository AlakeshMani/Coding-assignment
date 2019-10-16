#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import csv
import re

class Firewall:
    def __init__(self,filepath):
        self.filepath = filepath
# accept_packet function that performs validation
    def accept_packet(self, row): 
        if(row[0] not in ["inbound","outbound"]):  # validation of direction
            return False
        if(row[1] not in ["tcp","udp"]):           # validation of protocol
            return False
        if(int(row[2]) not in range(1,65536)):     # validation of port number
            return False
        if(not re.match("^(?=.*[^\.]$)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.?){4}$",row[3])):   # validation of IP address
            return False
        return True
# testing code
f = Firewall("G:\\assignment_sample.csv")        # passing input file location path to constructor of Firewall Class
with open(f.filepath,'r') as csvfile: 
    csvreader = csv.reader(csvfile)     
    for row in csvreader:
        print(f.accept_packet(row))              # passing each row of the input csv file to accept_packet function

