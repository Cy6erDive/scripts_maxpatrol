1. Export dhcp scopes with powershell
```
Get-DhcpServerv4Scope -ComputerName "DHCP_SERVER" | Select-Object ScopeId,SubnetMask,Name,State,StartRange,EndRange,LeaseDuration | Export-Csv 
DHCP_SERVER.csv -Delimiter "`t"
```
Copy files to .\dhcpscopes catalog

2. Export all tasks from MaxPatrol Console in one .xml file and copy it to .\tasks_mp catalog

3. Export 1 tasks from MaxPatrol Console in one .xml file named mp_taskTemplate.xml. We have to edit it. As xml structure might be the same but task and 
account IDs might be different. 
mp_taskTemplate.xml - template file used to create MP tasks from absent DHCP leases.

4. Run python3 dhcplmp2.py

File AbsentScopes.csv will be created with active and inactive scopes. After that import TAB separated AbsentScopes.csv to excel document (UTF-8 encoding).

5. You can import tasks from .\out_tasks catalog to MaxPatrol (only active DHCP scopes will be used!)
