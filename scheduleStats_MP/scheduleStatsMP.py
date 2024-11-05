
"""
##
#
#Script outputs statistics of scheduled tasks in Max Patrol 8 Vulnerability Scanner
#We can count number of tasks and hosts per day and understand the load of scanner
##
"""
from dataclasses import dataclass, field
import xml.etree.ElementTree as ET
import csv
import ipaddress
import matplotlib.pyplot as plt

@dataclass
class ScheduleJob:
    name: str = field(default='')
    time: str = field(default='')
    frozen: int = field(default=0) # Status of schedule, 1 is deactivated, 0 is activated
    tasksInSch: list[str] = field(default_factory=list) # TODO: Tasks count
    taskHosts: list[str] = field(default_factory=list)
    taskIPs: list[str] = field(default_factory=list)

def scans_to_csv(number, name, ips, hosts, time, scan_tasks):
    number = str(number)
    ips = str(ips).strip('[]').replace('\'', '')
    hosts = str(hosts).strip('[]').replace('\'', '')
    scanType = 'Audit, Compliance'

    if scan_tasks: # For stats
        scans = [number, name, ips, hosts, scanType, time, scan_tasks]
    else:
        scans = [number, name, ips, hosts, scanType, time]
    #print(scans)
    return scans

def time_decode(timer_type, param1, param2, job_status, start_time):
    once = 'Разовое' # Once
    daily = 'Ежедневно' # Every num day
    weekly = 'Еженедельно' # In every num week
    monthly = 'Ежемесячно' # Monthly
    start_time = start_time.split('T')[1] # Time of starting task
    returnPeriod = 'None'

    if job_status == 1: # If Schedule is frozen and deactivated return off
        returnPeriod = 'Отключено'
        return returnPeriod

    if timer_type == '0': # Once
        returnPeriod = once
    elif timer_type == '1': # Day
        if param1 == '1':
            returnPeriod = daily + ', ' + start_time
        for d in range(2, 32):
            if d == int(param1):
                returnPeriod = 'Каждый ' + str(d) + ' день месяца, ' + start_time

    elif timer_type == '2': # Week
        # Convert param2 to weekdays
        if param2[-1] == '0':
            param2[-1] = 'Sunday'
        elif param2[-1] == '1':
            param2[-1] = 'Monday'
        elif param2[-1] == '2':
            param2[-1] = 'Tuesday'
        elif param2[-1] == '3':
            param2[-1] = 'Wednesday'
        elif param2[-1] == '4':
            param2[-1] = 'Thursday'
        elif param2[-1] == '5':
            param2[-1] = 'Friday'
        elif param2[-1] == '6':
            param2[-1] = 'Saturday'
        daysOfWeek = ','.join(param2)
        if param1 == '1':
            returnPeriod = weekly + ', ' + daysOfWeek + ', ' + start_time
        elif int(param1) > 1:
            for w in range(2, 54):
                if w == int(param1):
                    returnPeriod = 'Каждую ' + str(w) + ' неделю, ' + daysOfWeek + ', ' + start_time
        elif int(param1) < 0:
            for w in range(-5, 0):
                if w == int(param1):
                    returnPeriod = str(abs(w)) + ' неделя месяца, ' + daysOfWeek + ', ' + start_time

    elif timer_type == '3': # Month
        dayOfMonth = int(param2[-1])
        if dayOfMonth == -1: # if last day
            param2[-1] = 'последний день месяца'
        daysOfMonth = ','.join(param2)
        if param1 == '1': # if monthly
            returnPeriod = monthly + ', ' + daysOfMonth + ', ' + start_time
        elif int(param1) > 1: # if several months
            for m in range(2, 13):
                if m == int(param1):
                    returnPeriod = 'Каждый ' + str(abs(m)) + ' месяц, ' + daysOfMonth + ', ' + start_time

    return returnPeriod

def time_stats(input_results):
    totalSchedules = 0
    totalSchedulesweek = 0
    totalHosts = 0
    totalTasks = 0
    frequency_schedules = {'Monday': 0, 'Tuesday': 0, 'Wednesday': 0, 'Thursday': 0,
                           'Friday': 0, 'Saturday': 0, 'Sunday': 0}
    frequency_hosts = {'Monday': 0, 'Tuesday': 0, 'Wednesday': 0, 'Thursday': 0,
                       'Friday': 0, 'Saturday': 0, 'Sunday': 0}
    frequency_tasks = {'Monday': 0, 'Tuesday': 0, 'Wednesday': 0, 'Thursday': 0,
                       'Friday': 0, 'Saturday': 0, 'Sunday': 0}

    # Stats by week
    for s in input_results[1:]:
        #print(s)
        if 'TEST SCHEDULE' not in s[1]: #If it is not test schedule - which is not lunched in fact
            if 'Отключено' not in s[5]:
                if 'Разовое' not in s[5]:
                    #print(s)
                    totalSchedules += 1
                    timeFrame = s[5].replace(' ', '').split(',')
                    #print(timeFrame)
                    for day in frequency_schedules:
                        #print(day)
                        if day in timeFrame:
                            #print(day + ' +')
                            frequency_schedules[day] += 1

                    # Stats by scanning task in schedules
                    # number, name, ips, hosts, systemid, manager, severity, scanType, time, scan_tasks
                    #print(s[9])
                    for tasksins in s[6]:
                        #print(tasksins)
                        totalTasks += 1
                        #print(totalTasks)
                        for day in frequency_tasks:
                            #print(day)
                            if day in timeFrame:
                                #print(day + ' +')
                                frequency_tasks[day] += 1

    # Stats by number of hosts
    for s in input_results[1:]:
        if 'TEST SCHEDULE' not in s[1]: # If it is not test schedule - which is not lunched in fact
            if s[5] != 'Отключено':
                if s[5] != 'Разовое':
                    #print(s)
                    numHostsPerTask = 0
                    timeFrame = s[5].replace(' ', '').split(',')
                    #print(timeFrame)

                    # Count IP addresses
                    ipRanges = s[2]
                    numOfIP = 0
                    #print(ipRanges)
                    if ipRanges:
                        ipRanges = ipRanges.replace(' ', '').split(',')
                        for net in ipRanges:
                            startIP = int(ipaddress.IPv4Address(str(net.split('-')[0])))
                            endIP = int(ipaddress.IPv4Address(str(net.split('-')[1])))
                            numOfIP += endIP - startIP + 1
                        #print('Num of IPs: ', numOfIP)

                    # Count FQDNs
                    FQDNames = s[3]
                    numOfFQDN = 0
                    #print(FQDNames)
                    if FQDNames:
                        FQDNames = FQDNames.replace(' ', '').split(',')
                        numOfFQDN += len(FQDNames)
                        #print('Num of FQDNs: ', numOfFQDN)

                    numHostsPerTask = numOfIP + numOfFQDN
                    #print('Num of Hosts per task: ', numHostsPerTask)
                    totalHosts += numHostsPerTask

                    # Count frequency of hosts for days
                    for day in frequency_hosts:
                        #print(day)
                        if day in timeFrame:
                            #print(day + ' +')
                            frequency_hosts[day] += numHostsPerTask

    # Count totalSchedules per week
    for key in frequency_schedules:
        #print(key)
        #print(frequency_schedules)
        totalSchedulesweek += frequency_schedules[key]

    print('---------------------------------')
    print('Stats by schedules:')
    print('---------------------------------')
    print('Total: ', totalSchedules)
    print('Total quantity per week: ', totalSchedulesweek)
    for key in frequency_schedules:
        dayOfWeek = key
        dayCount = frequency_schedules[key]
        percentage = (frequency_schedules[key] / totalSchedulesweek) * 100
        print(dayOfWeek + ': ' + str(dayCount) + ' - ' + str('{:0.1f}'.format(percentage)) + ' %')
    print('---------------------------------')

    print('---------------------------------')
    print('Weekly number of scanned hosts:')
    print('---------------------------------')
    print('Total quantity per week: ', totalHosts)
    for key in frequency_hosts:
        dayOfWeek = key
        hostCount = frequency_hosts[key]
        percentage = (frequency_hosts[key] / totalHosts) * 100
        print(dayOfWeek + ': ' + str(hostCount) + ' - ' + str('{:0.1f}'.format(percentage)) + ' %')
    print('---------------------------------\n')

    #Plotting data
    print(frequency_hosts.keys(), frequency_hosts.values())
    fig, ax = plt.subplots()
    ax.set_ylabel('Number of hosts')
    ax.set_xlabel('Days')
    ax.set_title('Weekly number of scanned hosts')
    r = plt.bar(frequency_hosts.keys(), frequency_hosts.values())
    ax.bar_label(r, padding=3)
    #ax.legend()
    plt.show()


# Open source XML file and Load XML elements
filenameXML = 'schedules.xml'
tree = ET.parse(filenameXML)
root = tree.getroot()
# Assign xml root elements
schedules = root[1]
tasks = root[7]


# Create list for results
results = [['#', 'Schedule Name', 'IP segment', 'Scan Type', 'Schedule Timeframe']]
resultsforstats = [['#', 'Schedule Name', 'IP segment', 'Scan Type', 'Schedule Timeframe',
                    'Tasks in Schedule']]
# ID number for results count
i = 1

"""
Parsing XML file
"""
for schedule in schedules.findall('./{http://www.ptsecurity.ru/import}schedule'): # iterate schedules in schedule root
    #print('------------------------------------------------')
    #print('Schedule: ', schedule.attrib)
    schedule_name = schedule.attrib['name'] # get schedule name
    schedule_status = int(schedule.attrib['frozen'])  # get schedule name - convert to int
    job = ScheduleJob(name=schedule_name, frozen=schedule_status)

    schedule_timer_param2 = [] # Create/clear list for second parameter of time. Goes to time_decode() function
    for schedule_timer in schedule[2]: # iterate schedule_timers in schedule and get time parameters
        #print('schedule_timer: ', schedule_timer.attrib) # schedule_timer
        schedule_timer_type = schedule_timer.attrib['timer_type']
        schedule_start_time = schedule_timer.attrib['start_time']
        schedule_timer_param1 = schedule_timer.attrib['param1']
        schedule_timer_param2.append(schedule_timer.attrib['param2'])
        if int(schedule_timer_type) < 4:
            job.time = time_decode(schedule_timer_type, schedule_timer_param1, schedule_timer_param2, job.frozen, schedule_start_time) # decode time
        # XML Timer: {'timer_type': '2', 'start_time': '2021-07-18T06:00:00', 'stop_time': '2037-07-19T23:59:00', 'param1': '-3', 'param2': '0'}

    for taskInSchedule in schedule[3]: # iterate tasks in schedule
        #print('taskInSchedule: ', taskInSchedule.attrib)
        taskInScheduleID = taskInSchedule.attrib['id'] # take task id from schedule
        taskInSchedule_name = taskInSchedule.attrib['name']
        job.tasksInSch.append(taskInSchedule_name)
        #print(type(taskInScheduleID))

        for task in tasks.findall('./{http://www.ptsecurity.ru/import}task'): # tasks, iterate tasks in tasks root , find ID and get its name and description
        #print('Iterate tasks: ', task.attrib)
            taskID = task.attrib['id']

            if int(taskInScheduleID) == int(taskID): # compare id from taskInSchedule and tasks
                #print('Task: ', task.attrib)
                task_name = task.attrib['name'] # get name of task
                task_description = task.attrib['description'] # get description of task
               #print(task_name, ' ', task_description, ' ', taskID)

                for task_profile in task[0]: # iterate profiles in each task
                    #print('task_profile: ', task_profile.attrib)

                    for host in task_profile[0]: # iterate hosts in each task_profile and get its values
                        #print('hosts: ', host.attrib)
                        task_hostname = host.attrib['primary'] # get hostname
                        task_startIP = host.attrib['from'] # get start IP
                        task_endIP = host.attrib['to'] # get end IP
                        if task_hostname:
                            if task_hostname not in job.taskHosts: # check if host is not unique
                                job.taskHosts.append(task_hostname) # if hostname no empty add to list
                        if task_startIP or task_endIP:
                            network = task_startIP + '-' + task_endIP
                            if network not in job.taskIPs: # check if ip addresses are not uniq (task profiles have repeated ip ranges)
                                job.taskIPs.append(network)

    """Append results from data to CSV with scans_to_csv function
    """
    resultsforstats.append(scans_to_csv(i, job.name, job.taskIPs, job.taskHosts, job.time, job.tasksInSch))
    i += 1  #ID for export

for i in resultsforstats:
    print(i)

"""Display statistics
"""
time_stats(resultsforstats)










