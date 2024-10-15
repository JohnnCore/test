# DIRECTORIES SCANNING
## gobuster:
- `gobuster dir -u 10.10.10.10/ -w /usr/share/seclists/Discovery/Web-Content/common.txt `
- `gobuster dir -u 10.10.10.171 -w /usr/share/dirb/wordlists/common.txt`

    ```
    -w, --wordlist string   Path to the wordlist
    -s` Positive status codes (will be overwritten with status-codes-blacklist if set). Can also handle ranges like 200,300-400,404.
    -b` Negative status codes (will override status-codes if set). Can also handle ranges like 200,300-400,404. (default "404")
    ```

## feroxbuster:
- `feroxbuster -u 10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/big.txt`
    - `-u` Host to scan
    - `-w` Wordlist 
    - `-k` Ignore tls

# SUBDOMAINS SCANNING
## DNS:
### wfuzz:
- `wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://app.microblog.htb/' -H 'Host: FUZZ.microblog.htb' --hw 11`

    - `-hw` Ignore the domains that return this number of words

### fuff
- `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.githubapp.com -t 90  `