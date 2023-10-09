# SMBSearch
## Overview
SMBSearch is a tool to enumerate SMB shares.

It is used to:
- Scan a target
- Enumerate accessible shares and files
- Identify files that contain hard-coded credentials (passwords, API Keys, etc.)

## Installation 
1. Install Pysmb
```
pip3 install pysmb
```
2. Clone or download the Github Repo

## Usage
Scan a target as anonymous
```
python3 smb_search.py -i 192.168.179.136
```
```
[Mon Oct  9 12:45:01 2023] Scanning \\192.168.179.136\ADMIN$
[Mon Oct  9 12:45:01 2023] No access to \\192.168.179.136\ADMIN$
[Mon Oct  9 12:45:01 2023] Scanning \\192.168.179.136\C$
[Mon Oct  9 12:45:01 2023] No access to \\192.168.179.136\C$
[Mon Oct  9 12:45:01 2023] Scanning \\192.168.179.136\IPC$
[Mon Oct  9 12:45:01 2023] No access to \\192.168.179.136\IPC$
[Mon Oct  9 12:45:01 2023] Scanning \\192.168.179.136\Share
[Mon Oct  9 12:45:01 2023] Found suspicious Password Document: \\192.168.179.136\Share\password.txt
[Mon Oct  9 12:45:01 2023] Found suspicious Text File: \\192.168.179.136\Share\password.txt
[Mon Oct  9 12:45:01 2023] Found suspicious Putty Format SSH Key: \\192.168.179.136\Share\putty.ppk
[Mon Oct  9 12:45:01 2023] Found suspicious Text File: \\192.168.179.136\Share\twilio.txt
[Mon Oct  9 12:45:01 2023] Found possible password in \\192.168.179.136\Share\password.txt: ('password', 'ILikeBeans123@')
[Mon Oct  9 12:45:01 2023] Found possible Twilio API Key in \\192.168.179.136\Share\twilio.txt: SKFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
[Mon Oct  9 12:45:01 2023] Scan completed.
```
