# Active Infrastructure Enumeration
## HTTP Headers
- `curl -I "http://${TARGET}"`

```
HTTP/1.1 200 OK
Date: Fri, 08 Mar 2024 14:49:34 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: 02a93f6429c54209e06c64b77be2180d=jucujsfvo14loqests15drfl34; path=/; HttpOnly
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Fri, 08 Mar 2024 14:49:44 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8
```

```
There are also other characteristics to take into account while fingerprinting web servers in the response headers. These are:

    X-Powered-By header: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.

    Cookies: Cookies are another attractive value to look at as each technology by default has its cookies. Some of the default cookie values are:
        .NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
        PHP: PHPSESSID=<COOKIE_VALUE>
        JAVA: JSESSION=<COOKIE_VALUE>
```

## WhatWeb
- `whatweb -a3 https://www.facebook.com -v`


# Active Subdomain Enumeration
## 1. Identifying Nameservers
- `nslookup -type=NS zonetransfer.me`

## 2. Testing for ANY and AXFR Zone Transfer
- `nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja`


