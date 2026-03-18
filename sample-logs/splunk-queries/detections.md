# Splunk Detection Queries

## 1. Failed Login Attempts
index=security sourcetype=WinEventLog:Security EventCode=4625
| stats count by user, src_ip
| where count > 5

## 2. Successful Login After Failures
index=security sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625)
| stats count by user, EventCode
| where EventCode=4625

## 3. Suspicious PowerShell Execution
index=security EventCode=4688 process="*powershell*"
| table _time, user, process, command_line

## 4. Multiple Logins from Same IP
index=security EventCode=4624
| stats dc(user) as unique_users by src_ip
| where unique_users > 3
