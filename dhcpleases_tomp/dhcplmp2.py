#!/usr/bin/python3

import os
from csv import reader, writer
import ipaddress
import xml.etree.ElementTree as ET
import shutil

# 1 Parse dhcp scopes from exported files
# 2: Parse XML exported tasks and find abscent scopes
# 3: Create separate task files for MaxPatrol for import

# Save results
def save_results(inlist, resultname):
    fileResults = open(resultname + '.csv', mode='w', encoding='utf8', newline='')
    resultwriter = writer(fileResults, delimiter='\t')
    resultwriter.writerows(inlist)
    fileResults.close()

# Function to return list of IP ranges abscent in MP tasks
def showabscentranges(dhcpscopes, mpatroltasks):
    abscentscope = [['Network', 'ScopeId', 'SubnetMask', 'Name', 'State', 'StartRange', 'EndRange', 'LeaseDuration']]
    scopesintasks = []
    scopesnotintasks = []

    # Iterate dhcp dataset and get IP networks
    for sc in dhcpscopes[1:]:
        scope = sc[0] + '/' + sc[1]
        #print(scope)
        scope = ipaddress.IPv4Network(scope)
        #print(scope)

        # Iterate MaxPatrol tasks dataset and compare
        for tsk in mpatroltasks[1:]:
            if tsk[2] and tsk[3] and (tsk[2] != '127.0.0.1' and tsk[3] != '127.0.0.1'):
                startip = ipaddress.IPv4Address(tsk[2])
                endip = ipaddress.IPv4Address(tsk[3])
                tskranges = ipaddress.summarize_address_range(startip, endip)
                #print('start ip:' + str(startip) + ' | end ip: ' + str(endip) + ' | sum range: ' + str(list(tskranges)))

                # Search IP from DHCP scope NOT in MP tasks
                for tskrange in tskranges:                      # Iterate IP ranges from MP tasks
                    #print('DEBUG> tskrange ' + str(tskrange) + ' ' + str(tskranges))

                    # Make list with unique DHCP scopes present in MP tasks
                    for ipinscope in scope:                         # each IP in each scope
                        #print('DEBUG> ipinscope ' + str(ipinscope) + ' ' + str(scope) + ' ' + str(tskrange))
                        if '/32' not in str(tskrange): # Do not include CIDR /32 ranges (otherwise miss a lot of scopes)
                            if ipinscope in tskrange:
                                #print('DEBUG> ipinscope ' + str(ipinscope) + ' ' + str(tskrange))
                                if scope not in scopesintasks:          # make list with unique DHCP scopes present in MP tasks
                                    scopesintasks.append(scope)

        # Make list and dataset with unique DHCP scopes that are abscent in MP tasks
        if scope not in scopesintasks and scope not in scopesnotintasks:
            scopesnotintasks.append(scope)
            sc.insert(0, str(scope))
            abscentscope.append(sc)

    # scopesintasks: list with unique DHCP scopes present in MP tasks
    # scopesnotintasks: list with unique DHCP scopes that are abscent in MP tasks

    # Create separate task files for MaxPatrol to import
    leasename = ''
    taskstartip = ''
    taskendip = ''
    for w in abscentscope[1:]:
        network = w[0]
        leasename = w[3]
        state = w[4]
        taskstartip = w[5]
        taskendip = w[6]
        if state != 'Inactive': # If DHCP lease is active on DHCP server then crate task file
            outputtask(net=network, taskname=leasename, taskstart=taskstartip, taskend=taskendip)

    return abscentscope

# Function -  write to new XML task file taskname, taskstart, taskend
# Requres mp_task.xml file in out_tasks folder
def outputtask(net, taskname, taskstart, taskend):
    pathtooutputtasks = os.getcwd() + '\\out_tasks\\'  # For windows
    outfilename = '[DHCP Lease] ' + taskname + '.xml'
    #shutil.copy(pathtooutputtasks + 'mp_taskTemplate.xml', pathtooutputtasks + outfilename)
    shutil.copy('mp_taskTemplate.xml', pathtooutputtasks + outfilename)
    print('Creating task: ', outfilename)

    ET.register_namespace('', "http://www.ptsecurity.ru/import")
    ET.register_namespace('xsd', "http://www.w3.org/2001/XMLSchema")
    ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")
    treeout = ET.parse(pathtooutputtasks + outfilename)
    rootout = treeout.getroot()
    rootout.set( "xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
    rootout.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")

    taskroot = rootout.find('{http://www.ptsecurity.ru/import}tasks')
    #print('DEBUG: taskn', taskroot)
    for taskn in taskroot:
        #print(taskn)
        taskn.set('name', '[DHCP Lease] ' + taskname)
        name = taskn.attrib.get('name')
        #scanner = taskn.attrib.get('scanner')
        taskn.set('description', taskname + ' ' + net)
        description = taskn.attrib.get('description')
        for tasknprofile in taskn[0]:
            #taskprofileid = tasknprofile.attrib.get('id')
            for hostnranges in tasknprofile[0]:
                # print(hostnranges.attrib)
                hostnranges.set('from', taskstart)
                hostnranges.set('to', taskend)
                hostranges_from = hostnranges.attrib.get('from')
                hostranges_to = hostnranges.attrib.get('to')

    treeout.write(pathtooutputtasks + outfilename, encoding='utf-8', xml_declaration=True)

    #print('DEBUG: ', name, description, hostranges_from, hostranges_to, hostname)


pathtoscopes = os.getcwd() + '\\dhcpscopes\\' # For windows
pathtotasks = os.getcwd() + '\\tasks_mp\\' # For windows

# Parse dhcp scopes from powershell results
scopedataset = [['ScopeId', 'SubnetMask', 'Name', 'State', 'StartRange', 'EndRange', 'LeaseDuration']]
for f in os.listdir(pathtoscopes):
    filename = f
    print('Parsing: ', filename)
    scopes = open(pathtoscopes + filename, mode='r', encoding='utf8', newline='\n')
    readscopes = reader(scopes, delimiter='\t')
    listscopes = list(readscopes)
    scopes.close()

    for row in listscopes[2:]:
        if row and row not in scopedataset:
            scopedataset.append(row)

# Debug
'''for i in scopedataset[0:5]:
    print(i)'''

# Parse maxpatrol tasks and add to dataset
mptasks = [['Task Name', 'Description', 'Start IP', 'End IP', 'Hostname']]
for f in os.listdir(pathtotasks):
    filename = f
    #print(filename)
    tree = ET.parse(pathtotasks + filename)
    root = tree.getroot()
    #print(root)
    #print(root.tag)

    for task in root.findall('{http://www.ptsecurity.ru/import}tasks'):
        #print(task)
        for taskname in task:
            #print(taskname.attrib)
            name = taskname.attrib.get('name')
            taskid = taskname.attrib.get('id')
            scanner = taskname.attrib.get('scanner')
            description = taskname.attrib.get('description')
            #print(name, id, scanner)
            for taskprofile in taskname[0]:
                taskprofileid = taskprofile.attrib.get('id')
                for hostranges in taskprofile[0]:
                    #print(hostranges.attrib)
                    hostname = hostranges.attrib.get('primary')
                    mptasks.append([name, description, hostranges.attrib.get('from'), hostranges.attrib.get('to'), hostname])
                    #print(ipranges)

# Debug
'''for i in mptasks[0:5]:
    print(i)'''

scopeabscentdataset = showabscentranges(scopedataset, mptasks)

#Print abscent
print('---')
print('Abscent scopes:')
for row in scopeabscentdataset:
    print(row)

# Save results
save_results(scopeabscentdataset, 'AbsentScopes')

print('Total DHCP scopes: ', len(scopedataset) - 1)
print('DHCP scopes not in MP tasks: ', len(scopeabscentdataset) - 1)
