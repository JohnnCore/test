# Domain Enumeration
## Identifying Hosts
```
$ sudo -E wireshark
```

```
$ sudo tcpdump -i ens224 
```

```
$ sudo responder -I ens224 -A 
```

```
$ fping -asgq 172.16.5.0/23
```

## Scan Alive hosts
focus on standard protocols typically seen accompanying AD services, such as DNS, SMB, LDAP, and Kerberos name a few.

```
$ sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```


