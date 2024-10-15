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

### Find Alive hosts
```
$ fping -asgq 172.16.5.0/23
```

### Scan Alive hosts
focus on standard protocols typically seen accompanying AD services, such as DNS, SMB, LDAP, and Kerberos name a few.

```
$ sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

## Identifying Users
```
$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```