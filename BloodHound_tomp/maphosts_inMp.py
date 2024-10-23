#!/usr/bin/python3

from csv import reader, writer
import ipaddress
import socket
import xml.etree.ElementTree as ET

# Save results
def save_results(inlist, resultname):
    fileResults = open(resultname + '.csv', mode='w', encoding='utf8')
    resultwriter = writer(fileResults, delimiter='\t')
    resultwriter.writerows(inlist)
    fileResults.close()

# Resolve fqdn to IP
def get_ip(dnsname):
    dnsname = dnsname.strip()
    try:
        addr = socket.gethostbyname(dnsname)
        return addr
    except socket.gaierror:
        return ''

# Function to return abscent IP addresses
def showabsentip(ad_hosts, mpatroltasks):
    abscent = [['#', 'Type', 'FQDN', 'IP', 'OS', 'Description']]
    ad_ipaddressInTasks = []
    ad_ipaddressNotInTasks = []

    # Iterate AD dataset and get IP address
    for i in ad_hosts[1:]:
        ad_ipaddress = i[3]
        if ad_ipaddress != 'DNS Error':
            ad_ipaddress = ipaddress.IPv4Address(ad_ipaddress)

            # Iterate MaxPatrol tasks dataset and compare
            for tsk in mpatroltasks[1:]:
                if tsk[2] and tsk[3] and (tsk[2] != '127.0.0.1' and tsk[3] != '127.0.0.1'):
                    startip = ipaddress.IPv4Address(tsk[2])
                    endip = ipaddress.IPv4Address(tsk[3])
                    tskranges = ipaddress.summarize_address_range(startip, endip)
                    for tskrange in tskranges:
                        if ad_ipaddress in tskrange:
                            if ad_ipaddress not in ad_ipaddressInTasks:
                                ad_ipaddressInTasks.append(ad_ipaddress)
                                print(str(ad_ipaddress), str(tskrange))

    # Iterate AD dataset and get IP address
    for i in ad_hosts[1:]:
        ad_ipaddress = i[3]
        if ad_ipaddress != 'DNS Error':
            ad_ipaddress = ipaddress.IPv4Address(ad_ipaddress)

            # Make list of absenthosts
            if ad_ipaddress not in ad_ipaddressInTasks and ad_ipaddress not in ad_ipaddressNotInTasks:
                abscent.append(i)

    return abscent


filename = 'computersList.csv'
hosts_list = open(filename, mode='r', encoding='utf8')
readhosts = reader(hosts_list, delimiter='\t')
listhosts = list(readhosts)
hosts_list.close

mptasks = [['Task Name', 'Description', 'Start IP', 'End IP', 'Hostname']]
filename = 'tasks.xml'
tree = ET.parse(filename)
root = tree.getroot()
for task in root.findall('{http://www.ptsecurity.ru/import}tasks'):
        print(task)
        for taskname in task:
            #print(taskname.attrib)
            name = taskname.attrib.get('name')
            taskid = taskname.attrib.get('id')
            scanner = taskname.attrib.get('scanner')
            description = taskname.attrib.get('description')
            for taskprofile in taskname[0]:
                taskprofileid = taskprofile.attrib.get('id')
                for hostranges in taskprofile[0]:
                    hostname = hostranges.attrib.get('primary')
                    fromip = hostranges.attrib.get('from')
                    toip = hostranges.attrib.get('to')
                    if not fromip and not toip and hostname: #If only hostname it task specified - resolve IP
                        fromip = get_ip(hostname)
                        toip = fromip

                    mptasks.append([name, description, fromip, toip, hostname])

# Debug
'''for i in mptasks[0:30]:
    print(i)'''

absenthosts = showabsentip(listhosts, mptasks)
save_results(absenthosts, 'absenthosts')
for i in absenthosts:
    print(i)
