## delete


# Directory Fuzzing
```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<URL>:<PORT>/FUZZ
```

* * *

# Extension Fuzzing
```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt -u http://<URL>:<PORT>/indexFUZZ
```

* * *

# Page Fuzzing
We will now use the same extension found previous.

```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<URL>:<PORT>/FUZZ.php
```

* * *

# Recursive Scanning
```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<URL>:<PORT>/FUZZ -recursion -recursion-depth 1 -e .php -v
```

* * *

# Parameters
## GET
```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<URL>:<PORT>/index.php?FUZZ=key -fs xxx
```

## POST
`Tip: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".`

```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<URL>:<PORT>/index.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

We can send a POST request with curl
```bash
$ curl http://<URL>:<PORT>/index.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

## Value 
After fuzzing a working parameter, we now have to fuzz the correct value.   

```bash
$ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

* * *

# Sub-domain Fuzzing
Add to /etc/hosts

```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.<IP/ADDRESS>:<PORT>/
```

* * *

# Vhosts Fuzzing
```bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<IP/ADDRESS>:<PORT>/ -H 'Host: FUZZ.<IP/ADDRESS>'
```
* * *

# Filtering Results
```bash
$ ffuf -h
```