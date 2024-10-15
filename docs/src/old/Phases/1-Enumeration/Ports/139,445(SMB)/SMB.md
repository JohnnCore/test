# SMB
## nmap:
- `nmap --script smb-os-discovery.nse -p445 10.10.10.40`

# Shares
- `smbclient -N -L \\\\10.129.42.253`
- `smbclient -U bob \\\\10.129.42.253\\users`

    - `-N` suppresses the password prompt
    - `-L` want to retrieve a list of available shares on the remote host
    
    - `get` download file to local machine

- `crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares` Show avaiable chares

- `rpcclient 10.129.202.5 -U ""` 

```
Query	Description
srvinfo	Server information.
enumdomains	Enumerate all domains that are deployed in the network.
querydominfo	Provides domain, server, and user information of deployed domains.
netshareenumall	Enumerates all available shares.
netsharegetinfo <share>	Provides information about a specific share.
enumdomusers	Enumerates all domain users.
queryuser <RID>	Provides information about a specific user.
```