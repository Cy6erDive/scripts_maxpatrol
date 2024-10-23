#!/usr/bin/python3

import os
import json
from csv import reader, writer
import socket
import time

# Open and parse bloodhound computer names
# Resolve computer names to IP addresses
# Save result to .CSV dataset



# Save results
def save_results(inlist, resultname):
    fileResults = open(resultname + '.csv', mode='w', encoding='utf8', newline='')
    resultwriter = writer(fileResults, delimiter='\t')
    resultwriter.writerows(inlist)
    fileResults.close()

# Resolve fqdn to IP
def get_ip(dnsname):
    time.sleep(1)
    dnsname = dnsname.strip()
    try:
        addr = socket.gethostbyname(dnsname)
        return addr
    except socket.gaierror:
        return 'DNS Error'


# Open file with computers in json
# Request used in BloodHound- MATCH (m:Computer) RETURN m
filename = 'computers.json'
bh_computers = open(filename, mode='r', encoding='utf8')
computers_load = json.load(bh_computers)

hosts = [['#', 'Type', 'FQDN', 'IP', 'OS', 'Description']]
hosttype = ''
fqdn = 'localhost'
ip = ''
os = ''
descr = ''
i = 0
for node in computers_load["nodes"]:
    i += 1
    if node["type"] == "Computer":
        print(node["type"])
        hosttype = node["type"]
        if "operatingsystem" in node["props"]:
            print(node["props"]["operatingsystem"])
            os = node["props"]["operatingsystem"]
        else:
            os = ''
        fqdn = node["props"]["name"]
        print(node["props"]["name"])
        if "description" in node["props"]:
            descr = node["props"]["description"]
            print(node["props"]["description"])
        else:
            descr = ''
        if 'Windows' in os: # include only Windows OS
            ip = get_ip(fqdn) # Resolve IP address
            hosts.append([i, hosttype, fqdn, ip, os, descr])

#Print Results
stats = {}
for r in hosts[1:]:
    os = r[4]
    if os in stats:
        stats[os] += 1
    else:
        stats[os] = 1
    print(r)

#Print statistics by OS
for s in stats:
    print(s, stats[s])

#Save results
save_results(hosts, 'computersList')