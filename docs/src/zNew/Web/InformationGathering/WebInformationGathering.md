## delete


# WHOIS
```bash
$ whois $TARGET
```

* * *

# DNS
## Nslookup & DIG
### Querying: A Records
`nslookup $TARGET`

`dig facebook.com @1.1.1.1`


### Querying: A Records for a Subdomain
`nslookup -query=A $TARGET`

`dig a www.facebook.com @1.1.1.1`

### Querying: PTR Records for an IP Address
`nslookup -query=PTR 31.13.92.36`

`dig -x 31.13.92.36 @1.1.1.1`

### Querying: ANY Existing Records

`nslookup -query=ANY $TARGET`

`dig any google.com @8.8.8.8`

`dig any cloudflare.com @8.8.8.8`

### Querying: TXT Records
`COR33@htb[/htb]$ nslookup -query=TXT $TARGET`

`dig txt facebook.com @1.1.1.1`

### Querying: MX Records
`nslookup -query=MX $TARGET`

`dig mx facebook.com @1.1.1.1`

### Nslookup
`nslookup $TARGET`

### WHOIS
` whois 157.240.199.35`

# Active Infrastructure Identification
## HTTP Headers
```bash
curl -I "http://${TARGET}"
```

There are also other characteristics to take into account while fingerprinting web servers in the response headers. These are:

- X-Powered-By header: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.

- Cookies: Cookies are another attractive value to look at as each technology by default has its cookies. Some of the default cookie values are:
    - .NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
    - PHP: PHPSESSID=<COOKIE_VALUE>
    - JAVA: JSESSION=<COOKIE_VALUE>

## WhatWeb
```bash
$ whatweb -a3 https://www.facebook.com -v
```

## Wappalyzer

## wafw00f
```bash
$ pip3 install git+https://github.com/EnableSecurity/wafw00f
$ wafw00f <domain>
```

# Subdomains 
```bash
$ dnsenum --enum inlanefreight.com -f  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 
```