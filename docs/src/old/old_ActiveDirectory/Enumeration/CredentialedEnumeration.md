# Credentialed Enumeration 
## Linux
### CrackMapExec [https://github.com/byt3bl33d3r/CrackMapExec]
```
$ crackmapexec -h
```
MSSQL, SMB, SSH, and WinRM credentials

#### CME Options (SMB)
```
$ crackmapexec smb -h
```

#### CME - Domain User Enumeration
We start by pointing CME at the Domain Controller.

```
$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```

#### CME - Domain Group Enumeration
```
$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```

#### CME - Logged On Users
```
$ sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```

#### CME Share Searching
```
$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

#### Spider_plus
```
$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```

### SMBMap [https://github.com/ShawnDEvans/smbmap]
#### SMBMap To Check Access
```
$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```

#### Recursive List Of All Directories
```
$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

### rpcclient [https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html]
```
$ rpcclient -U "" -N 172.16.5.5
```

#### Enumdomusers
```
rpcclient $> enumdomusers
```

#### RPCClient User Enumeration By RID
```
rpcclient $> queryuser 0x457
```

### Impacket Toolkit
#### Psexec.py [https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py]
To connect to a host with psexec.py, we need credentials for a user with local administrator privileges.
```
$ psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

#### Using wmiexec.py [https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py]
```
$ wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```

### Windapsearch
#### Windapsearch - Domain Admins
```
$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```

#### Windapsearch - Privileged Users
```
$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

### Bloodhound.py [https://github.com/fox-it/BloodHound.py]
Once we have domain credentials, we can run the BloodHound.py BloodHound ingestor from our Linux attack host. BloodHound is one of, if not the most impactful tools ever released for auditing Active Directory security, and it is hugely beneficial for us as penetration testers. We can take large amounts of data that would be time-consuming to sift through and create graphical representations or "attack paths" of where access with a particular user may lead. We will often find nuanced flaws in an AD environment that would have been missed without the ability to run queries with the BloodHound GUI tool and visualize issues. The tool uses graph theory to visually represent relationships and uncover attack paths that would have been difficult, or even impossible to detect with other tools. The tool consists of two parts: the SharpHound collector written in C# for use on Windows systems, or for this section, the BloodHound.py collector (also referred to as an ingestor) and the BloodHound GUI tool which allows us to upload collected data in the form of JSON files. Once uploaded, we can run various pre-built queries or write custom queries using Cypher language. The tool collects data from AD such as users, groups, computers, group membership, GPOs, ACLs, domain trusts, local admin access, user sessions, computer and user properties, RDP access, WinRM access, etc.

```
$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 
```

#### Upload the Zip File into the BloodHound GUI
```
$ sudo neo4j start
$ zip -r ilfreight_bh.zip *.json

$ bloodhound 
```

## Windows
### ActiveDirectory PowerShell Module
```
PS > Get-Module
```

#### Load ActiveDirectory Module
```
PS > Import-Module ActiveDirectory
PS > Get-Module
```

#### Get Domain Info
```
PS > Get-ADDomain
```

#### Get-ADUser
```
PS > Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

#### Checking For Trust Relationships
```
PS > Get-ADTrust -Filter *
```

#### Group Enumeration
```
PS > Get-ADGroup -Filter * | select name
```

#### Detailed Group Info
```
PS > Get-ADGroup -Identity "Backup Operators"
```

#### Group Membership
```
PS > Get-ADGroupMember -Identity "Backup Operators"
```

### PowerView [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1]
#### Domain User Information
```
PS > Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

#### Recursive Group Membership
```
PS >  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

#### Trust Enumeration
```
PS C:\htb> Get-DomainTrustMapping
```

#### Testing for Local Admin Access
```
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

#### Finding Users With SPN Set
```
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

### SharpView [https://github.com/dmchell/SharpView]
```
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend
```

### Snaffler [https://github.com/SnaffCon/Snaffler]
Snaffler is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories. Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment. Snaffler requires that it be run from a domain-joined host or in a domain-user context.


```
PS C:\htb> .\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data
```

### SharpHound [https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors]
```
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```

### BloodHound [https://github.com/BloodHoundAD/BloodHound]

## Living Off the Land
### Quick Checks Using PowerShell
```
PS C:\htb> Get-Module
PS C:\htb> Get-ExecutionPolicy -List
PS C:\htb> Get-ChildItem Env: | ft key,value

```
### Downgrade Powershell
```
PS C:\htb> Get-host
PS C:\htb> powershell.exe -version 2
PS C:\htb> Get-host
PS C:\htb> get-module

```
### Checking Defenses
#### Firewall Checks
```
PS C:\htb> netsh advfirewall show allprofiles
```

#### Windows Defender Check (from CMD.exe)
```
C:\htb> sc query windefend
```

#### Get-MpComputerStatus
```
PS C:\htb> Get-MpComputerStatus
```

### Am I Alone?
#### Using qwinsta
```
PS C:\htb> qwinsta
```

### Network Information

|Networking Commands            |   Description                                 
|------------------------------ | ---------------------------------------------
|arp -a	Lists all               |known hosts stored in the arp table.
|ipconfig /all	                |Prints out adapter settings for the host. We can figure out the network segment from here.
|route print	                |Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host.
|netsh advfirewall show state   |Displays the status of the host's firewall. We can determine if it is active and filtering traffic.

#### Using arp -a
```
PS C:\htb> arp -a
```

#### Viewing the Routing Table
```
PS C:\htb> route print
```

`Using arp -a and route print will not only benefit in enumerating AD environments, but will also assist us in identifying opportunities to pivot to different network segments in any environment. These are commands we should consider using on each engagement to assist our clients in understanding where an attacker may attempt to go following initial compromise.`

### Windows Management Instrumentation (WMI)
#### Quick WMI checks
|Command | 	Description
|------------------------------ | -----------------------------
|wmic qfe get Caption,Description,HotFixID,InstalledOn	Prints the patch level and description of the Hotfixes applied
|wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List	Displays basic host information to include any attributes within the list
|wmic process list /format:list	A listing of all processes on host
|wmic ntdomain list /format:list	Displays information about the Domain and Domain Controllers
|wmic useraccount list /format:list	Displays information about all local accounts and any domain accounts that have logged into the device
|wmic group list /format:list	Information about all local groups
|wmic sysaccount list /format:list	Dumps information about any system accounts that are being used as service accounts.



### Net Commands
| Command |	Description
|------------------------------ | -----------------------------
| net accounts	| Information about password requirements
| net accounts /domain	 | Password and lockout policy
| net group /domain	| Information about domain groups
| net group "Domain Admins" /domain	| List users with domain admin privileges
| net group "domain computers" /domain	| List of PCs connected to the domain
| net group "Domain Controllers" /domain	| List PC accounts of domains controllers
| net group <domain_group_name> /domain	| User that belongs to the group
| net groups /domain	| List of domain groups
| net localgroup	| All available groups
| net localgroup administrators /domain	| List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default)
| net localgroup Administrators	| Information about a group (admins)
| net localgroup administrators [username] /add	| Add user to administrators
| net share |	Check current shares
| net user <ACCOUNT_NAME> /domain	| Get information about a user within the domain
| net user /domain	| List all users of the domain
| net user %username%	| Information about the current user
| net use x: \computer\share	| Mount the share locally
| net view	| Get a list of computers
| net view /all /domain[:domainname]	| Shares on the domains
| net view \computer /ALL	| List shares of a computer
| net view /domain	| List of PCs of the domain

#### Net Commands Trick
If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing net1 instead of net will execute the same functions without the potential trigger from the net string.

### Dsquery
#### User Search
```
PS C:\htb> dsquery user

```

#### Computer Search
PS C:\htb> dsquery computer


#### Wildcard Search
PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

#### Users With Specific Attributes Set (PASSWD_NOTREQD)
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

#### Searching for Domain Controllers
PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
