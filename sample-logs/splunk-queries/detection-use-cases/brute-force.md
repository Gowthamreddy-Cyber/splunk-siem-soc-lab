# Brute Force Attack Detection

## Description
Detect multiple failed login attempts from a single IP address.

## Logic
- Monitor EventCode 4625 (failed login)
- Identify repeated attempts from same IP

## SPL Query
index=security EventCode=4625
| stats count by src_ip
| where count > 10

## Risk
Indicates possible brute force attack.

## Action
- Block IP
- Investigate affected accounts
