# SMBSearch
## Overview
SMBSearch is a tool to enumerate SMB shares.

It is used to:
- Scan a target
- Enumerate accessible shares and files
- Identify files that contain hard-coded credentials (passwords, API Keys, etc.)

## Installation 
1. Clone or download the repo
2. Install pysmb
```
pip3 install pysmb
```
3. Enjoy :)

## Usage
Scan a target as anonymous and download suspicious files
```
python3 smb_search.py -i 192.168.179.136 -g
```

Scan a list of targets as a specified domain user
```
python3 smb_search.py -l ips.txt -u username -p password -d contoso.com
```
