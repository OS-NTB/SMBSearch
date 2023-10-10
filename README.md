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

Scan a list of targets as a specified domain user
```
python3 smb_search.py -l ips.txt -u username -p password -d contoso.com
```
