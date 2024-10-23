1. Extract hosts with BloodHound(v.4.3.1)
`MATCH (m:Computer) RETURN m`
Save to file computers.json and move to directory with script

2. Export all tasks from MaxPatrol Console (xml format) and save in file tasks.xml to the directory with script

3. run python3 fqdnToIP.py
File computersList.csv will be created with resolved IP addresses(need access to internal DNS as it looks up each IP)

4. run python3 maphosts_inMp.py
File absenthosts.csv will be created with absent hosts in MaxPatrol tasks

5. After that import TAB separated absenthosts.csv to excel document (UTF-8 encoding).

Using results you can lookup IP ranges in Netbox or in any other IP management software.
